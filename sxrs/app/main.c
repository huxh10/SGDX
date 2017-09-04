#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include "app_types.h"
#include "shared_types.h"
#include "server.h"
#include "msg_handler.h"
#include "epoll_utils.h"

#ifdef W_SGX
#include "route_process_w_sgx.h"
#else
#include "route_process_wo_sgx.h"
#endif

static struct {
    net_conf_t net;
    char *asn_2_id_file;
    char *as_ips_file;
    char *filter_file;
    char *rank_file;
    char *rib_file_dir;
    int verbose;
} g_cfg = {{NULL, 0, NULL, 0}, NULL, NULL, NULL, NULL, NULL, VERBOSE};

static void print_help(void)
{
    static const char *help =

        "Valid options:\n"
        "   -h, --help                  display this help and exit\n"
        "   -b, --bgp_serv_addr ADDR    specify the bgp server listening address, default is localhost\n"
        "   -p, --bgp_serv_port PORT    specify the bgp server listening port, default is 6000\n"
        "   -c, --pctrlr_serv_addr ADDR specify the participant controller server listening, default is localhost\n"
        "   -t, --pctrlr_serv_port PORT specify the participant controller server port, default is 6666\n"
        "   -v, --verbose num           0(default): print selected time, 4: print bgp_msgs and the ribs, 5: print as policies\n"
        "   -a, --asn_2_id_file FILE    specify an asn to id configuration file, e.g. ../examples/test-rs/config/asn_2_id.cfg\n"
        "   -i, --as_ips_file   FILE    specify as connected port ips file, e.g. ../examples/test-rs/config/as_ips.cfg\n"
        "   -f, --filter_file   FILE    specify filtering policy file, e.g. ../examples/test-rs/bgp_policies/peers_uni_62_020.cfg\n"
        "   -r, --rank_file     FILE    specify ranking policy file, e.g. ../examples/test-rs/bgp_policies/prefer_rand_62.cfg\n"
        "   -d, --rib_file_dir  DIR     specify rib directory name to load ribs from file, e.g. ../examples/test-rs/ribs/\n"
        "\n";

    printf("%s\n", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hb:p:c:t:v:a:i:f:r:d:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"bgp_serv_addr", required_argument, NULL, 'b'},
        {"bgp_serv_port", required_argument, NULL, 'p'},
        {"pctrlr_serv_addr", required_argument, NULL, 'c'},
        {"pctrlr_serv_port", required_argument, NULL, 't'},
        {"verbose", required_argument, NULL, 'v'},
        {"asn_2_id_file", required_argument, NULL, 'a'},
        {"as_ips_file", required_argument, NULL, 'i'},
        {"filter_file", required_argument, NULL, 'f'},
        {"rank_file", required_argument, NULL, 'r'},
        {"rib_file_dir", required_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
            case 'h':
                print_help();
                exit(0);

            case 'b':
                g_cfg.net.bgp_serv_addr = optarg;
                break;

            case 'p':
                g_cfg.net.bgp_serv_port = atoi(optarg);

            case 'c':
                g_cfg.net.pctrlr_serv_addr = optarg;
                break;

            case 't':
                g_cfg.net.pctrlr_serv_port = atoi(optarg);
                break;

            case 'v':
                g_cfg.verbose = atoi(optarg);
                break;

            case 'a':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    g_cfg.asn_2_id_file = optarg;
                    break;
                }

            case 'i':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    g_cfg.as_ips_file = optarg;
                    break;
                }

            case 'f':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    g_cfg.filter_file = optarg;
                    break;
                }

            case 'r':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    g_cfg.rank_file = optarg;
                    break;
                }

            case 'd':
                g_cfg.rib_file_dir = optarg;
                break;

            default:
                print_help();
                exit(-1);
        }
    }

    return;
}

static void load_cfg(as_cfg_t *p_as_cfg)
{
    uint32_t i, j;
    int fscanf_ret;
    FILE *fp;
    uint32_t tmp_size, tmp_id;
    char *tmp_line, *delimiter = " ", *token, *p_save;
    size_t len;
    ssize_t read;
    assert(p_as_cfg != NULL);

    // FILE#1: asn_2_id file
    if ((fp = fopen(g_cfg.asn_2_id_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.asn_2_id_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &p_as_cfg->as_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    p_as_cfg->as_id_2_n = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_id_2_n);
    if (!p_as_cfg->as_id_2_n) {
        fprintf(stderr, "Malloc error for p_as_cfg->as_id_2_n [%s]\n", __FUNCTION__);
        exit(-1);
    }
    // the second line is about the asn list
    for (i = 0; i < p_as_cfg->as_size; i++) {
        fscanf_ret = fscanf(fp, " %u", &p_as_cfg->as_id_2_n[i]);
        assert(fscanf_ret == 1);
    }
    fscanf_ret = fscanf(fp, "\n");
    assert(fscanf_ret == 0);
    fclose(fp);

    // FILE#2: as_ips_file
    if ((fp = fopen(g_cfg.as_ips_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.as_ips_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &tmp_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    assert(tmp_size == p_as_cfg->as_size);
    p_as_cfg->as_ips = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_ips);
    if (!p_as_cfg->as_ips) {
        fprintf(stderr, "malloc error for p_as_cfg->as_ips [%s]\n", __FUNCTION__);
        exit(-1);
    }
    // the next lines about each AS ips
    for (i = 0; i < p_as_cfg->as_size; i++) {
        read = getline(&tmp_line, &len, fp);
        assert(read != 0);
        tmp_line[read - 1] = 0;             // strip '\n'
        token = strtok_r(tmp_line, delimiter, &p_save);
        tmp_size = atoi(token);
        p_as_cfg->as_ips[i].ip_num = tmp_size;
        p_as_cfg->as_ips[i].ips = malloc(tmp_size * sizeof *p_as_cfg->as_ips[i].ips);
        if (!p_as_cfg->as_ips[i].ips) {
            fprintf(stderr, "malloc error for p_as_cfg->as_ips[%d].ips [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < tmp_size; j++) {
            token = strtok_r(0, delimiter, &p_save);
            p_as_cfg->as_ips[i].ips[j] = strdup(token);
        }
    }
    SAFE_FREE(tmp_line);
    fclose(fp);
    fprintf(stderr, "load as ips done [%s]\n", __FUNCTION__);

    // alloc memory for as_policies
    p_as_cfg->as_policies = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies);
    if (!p_as_cfg->as_policies) {
        fprintf(stderr, "Malloc error for p_as_cfg->as_policies [%s]\n", __FUNCTION__);
        exit(-1);
    }
    for (i = 0; i < p_as_cfg->as_size; i++) {
        p_as_cfg->as_policies[i].import_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].import_policy);
        if (!p_as_cfg->as_policies[i].import_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].import_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // whitelist, set default value false
            p_as_cfg->as_policies[i].import_policy[j] = 0;
        }
        // self is true
        p_as_cfg->as_policies[i].import_policy[i] = 1;
        p_as_cfg->as_policies[i].export_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].export_policy);
        if (!p_as_cfg->as_policies[i].export_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].export_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // whitelist, set default value false
            p_as_cfg->as_policies[i].export_policy[j] = 0;
        }
        // self is true
        p_as_cfg->as_policies[i].export_policy[i] = 1;
        p_as_cfg->as_policies[i].selection_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].selection_policy);
        if (!p_as_cfg->as_policies[i].selection_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].selection_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
    }

    // FILE#3: filter_file
    if ((fp = fopen(g_cfg.filter_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.filter_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &tmp_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    assert(tmp_size == p_as_cfg->as_size);
    // the next lines are about peering relationship of each ASes
    for (i = 0; i < p_as_cfg->as_size; i++) {
        // import/export policy
        fscanf_ret = fscanf(fp, "%u", &tmp_size);
        assert(fscanf_ret == 1);
        for (j = 0; j < tmp_size; j++) {
            fscanf_ret = fscanf(fp, " %u", &tmp_id);
            assert(fscanf_ret == 1);
            p_as_cfg->as_policies[i].import_policy[tmp_id] = 1;
            p_as_cfg->as_policies[i].export_policy[tmp_id] = 1;
        }
        fscanf_ret = fscanf(fp, "\n");
        assert(fscanf_ret == 0);
    }
    fclose(fp);

    // FILE#4: rank_file
    if ((fp = fopen(g_cfg.rank_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.rank_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &tmp_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __FUNCTION__);
        exit(-1);
    }
    assert(tmp_size == p_as_cfg->as_size);
    // the next lines are about advertiser preference of each ASes
    for (i = 0; i < p_as_cfg->as_size; i++) {
        // selection policy
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // tmp_id represents priority
            fscanf_ret = fscanf(fp, " %u", &tmp_id);
            assert(fscanf_ret == 1);
            p_as_cfg->as_policies[i].selection_policy[j] = tmp_id;
        }
        fscanf_ret = fscanf(fp, "\n");
        assert(fscanf_ret == 0);
    }
    fclose(fp);

    if (g_cfg.verbose == 5) {
        for (i = 0; i < p_as_cfg->as_size; i++) {
            printf("AS %u asn %u ips:\n", i, p_as_cfg->as_id_2_n[i]);
            for (j = 0; j < p_as_cfg->as_ips[i].ip_num; j++) {
                printf("%s ", p_as_cfg->as_ips[i].ips[j]);
            }
            printf("\n");
            printf("AS %u import_policy:\n", i);
            for (j = 0; j < p_as_cfg->as_size; j++) {
                printf("%u ", p_as_cfg->as_policies[i].import_policy[j]);
            }
            printf("\n");
            printf("AS %u export_policy:\n", i);
            for (j = 0; j < p_as_cfg->as_size; j++) {
                printf("%u ", p_as_cfg->as_policies[i].export_policy[j]);
            }
            printf("\n");
            printf("AS %u selection_policy:\n", i);
            for (j = 0; j < p_as_cfg->as_size; j++) {
                printf("%u ", p_as_cfg->as_policies[i].selection_policy[j]);
            }
            printf("\n");
            printf("\n");
        }
    }

    // FILE#5: rib files, contents processed inside enclave
    if (g_cfg.rib_file_dir) p_as_cfg->rib_file_dir = strdup(g_cfg.rib_file_dir);
}

int main(int argc, char *argv[])
{
    int efd;
    as_cfg_t as_cfg = {0, NULL, NULL, NULL, NULL};

    parse_args(argc, argv);
    if (!g_cfg.asn_2_id_file || !g_cfg.filter_file || !g_cfg.rank_file) {
        printf("Please input configuration file name\n");
        exit(-1);
    }
    if (!g_cfg.net.bgp_serv_addr) g_cfg.net.bgp_serv_addr = "127.0.0.1";
    if (!g_cfg.net.bgp_serv_port) g_cfg.net.bgp_serv_port = 6000;
    if (!g_cfg.net.pctrlr_serv_addr) g_cfg.net.pctrlr_serv_addr = "127.0.0.1";
    if (!g_cfg.net.pctrlr_serv_port) g_cfg.net.pctrlr_serv_port = 6666;

    // initialization
    load_cfg(&as_cfg);
#ifdef W_SGX
    init_w_sgx(&as_cfg, g_cfg.verbose);
#else
    init_wo_sgx(&as_cfg, g_cfg.verbose);
#endif
    msg_handler_init(&as_cfg);
    efd = epoll_init();
    server_init(efd, &g_cfg.net, as_cfg.as_size);
    create_start_signal();

    // run
    epoll_run(efd);

    return 0;
}
