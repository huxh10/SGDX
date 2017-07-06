#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include "app_types.h"
#include "shared_types.h"
#include "server.h"
#include "epoll_utils.h"

#ifdef W_SGX
#include "route_process_w_sgx.h"
#else
#include "route_process_wo_sgx.h"
#endif

static struct {
    net_conf_t net;
    char *asn_2_id_file;
    char *filter_file;
    char *rank_file;
    char *rib_file_dir;
    int verbose;
} g_cfg = {{NULL, 0, NULL, 0}, NULL, NULL, NULL, NULL, VERBOSE};

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
    static const char *optstr = "hb:p:c:t:v:a:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"bgp_serv_addr", required_argument, NULL, 'b'},
        {"bgp_serv_port", required_argument, NULL, 'p'},
        {"pctrlr_serv_addr", required_argument, NULL, 'c'},
        {"pctrlr_serv_port", required_argument, NULL, 't'},
        {"verbose", required_argument, NULL, 'v'},
        {"asn_2_id_file", required_argument, NULL, 'a'},
        {"filter_file", required_argument, NULL, 'f'},
        {"rank_file", required_argument, NULL, "r"},
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
    uint32_t i, j, r;
    int fscanf_ret;
    FILE *fp;
    uint32_t tmp_size, tmp_id, tmp_asn;
    asn_map_t *asmap_entry;
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
    // construct asn_2_id map
    for (i = 0; i < p_as_cfg->as_size; i++) {
        asmap_entry = malloc(sizeof(asn_map_t));
        if (!asmap_entry) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_n_2_id, id:%d [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        asmap_entry->as_n = p_as_cfg->as_id_2_n[i];
        asmap_entry->as_id = id;
        HASH_ADD_INT(p_as_cfg->as_n_2_id, asmap_entry->as_n, asmap_entry);
    }
    fclose(fp);

    // alloc memory for as_policies
    p_as_cfg->as_policies = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies);
    if (!p_as_cfg->as_policies) {
        fprintf(stderr, "Malloc error for p_as_cfg->as_policies [%s]\n", __FUNCTION__);
        exit(-1);
    }
    for (i = 0; i < p_as_cfg->as_size; i++) {
        p_as_cfg->as_policies[i].active_parts = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].active_parts);
        if (!p_as_cfg->as_policies[i].active_parts) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].active_parts [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // whitelist, default is none
            p_as_cfg->as_policies[i].active_parts[j] = 0;
        }
        p_as_cfg->as_policies[i].import_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].import_policy);
        if (!p_as_cfg->as_policies[i].import_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].import_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // whitelist, default is none
            p_as_cfg->as_policies[i].import_policy[j] = 0;
        }
        p_as_cfg->as_policies[i].export_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].export_policy);
        if (!p_as_cfg->as_policies[i].export_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].export_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
        for (j = 0; j < p_as_cfg->as_size; j++) {
            // whitelist, default is none
            p_as_cfg->as_policies[i].export_policy[j] = 0;
        }
        p_as_cfg->as_policies[i].selection_policy = malloc(p_as_cfg->as_size * sizeof *p_as_cfg->as_policies[i].selection_policy);
        if (!p_as_cfg->as_policies[i].selection_policy) {
            fprintf(stderr, "Malloc error for p_as_cfg->as_policies[%d].selection_policy [%s]\n", i, __FUNCTION__);
            exit(-1);
        }
    }

    // FILE#2: filter_file
    if ((fp = fopen(g_cfg.filter_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.filter_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &tmp_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __function__);
        exit(-1);
    }
    assert(tmp_size == g_cfg.as_size);
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

    // FILE#3: rank_file
    if ((fp = fopen(g_cfg.rank_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", g_cfg.rank_file, __FUNCTION__);
        exit(-1);
    }
    // the first line is about the as size
    if (fscanf(fp, "%u\n", &tmp_size) != 1) {
        fprintf(stderr, "illegal as number format [%s]\n", __function__);
        exit(-1);
    }
    assert(tmp_size == g_cfg.as_size);
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

    // FILE#4: rib files
    if (!g_cfg.rib_file_dir) return;
    int dir_len = strlen(g_cfg.rib_file_dir);
    // 9 is for rib name (8), such as rib_1000, and '\0' (1)
    char rib_file[dir_len + 9] = {0};
    memcpy(rib_file, g_cfg.rib_file_dir, dir_len);
    char *line = NULL;  // buffer address
    size_t len = 0;     // allocated buffer size
    ssize_t read;
    char *delimiter = " ", *token, *p_save, *s_tmp;
    // allocate ribs memory
    g_cfg.loaded_ribs = malloc(g_cfg.as_size * sizeof *g_cfg.loaded_ribs);
    if (!g_cfg.loaded_ribs) {
        fprintf(stderr, "Malloc error for g_cfg.loaded_ribs [%s]\n", __FUNCTION__);
        exit(-1);
    }
    for (i = 0; i < g_cfg.as_size; i++) {
        g_cfg.loaded_ribs[i] = NULL;
    }
    rib_map_t *p_rib_entry = NULL;
    route_t *p_route = malloc(sizeof *p_route);
    if (!p_route) {
        fprintf(stderr, "Malloc error for p_route [%s]\n", __FUNCTION__);
        exit(-1);
    }
    reset_route(p_route);
    for (i = 0; i < p_as_cfg->as_size; i++) {
        sprinf(rib_file + dir_len, "rib_%d", i);
        if ((fp = fopen(rib_file, "r")) == NULL) {
            fprintf(stderr, "can not open file: %s [%s]\n", rib_file, __FUNCTION__);
            exit(-1);
        }
        while ((read = getline(&line, &len, fp)) != -1) {
            if (!strncmp("PREFIX: ", line, 8)) {
                p_route->prefix = strndup(line+8, read-9);  // "PREFIX: " is first 8 bytes, "\n" is the last byte
            } else if (!strncmp("FROM: ", line, 6)) {
                token = strtok_r(line, delimiter, &p_save);
                token = strtok_r(0, delimiter, &p_save);
                p_route->neighbor = strdup(token);
                token = strtok_r(0, delimiter, &p_save);
                tmp_asn = atoi(token+2);                     // ASXXX
                HASH_FIND_INT(g_cfg.as_n_2_id, &tmp_asn, asmap_entry);
                tmp_id = asmap_entry->as_id;
            } else if (!strncmp("ORIGIN: ", line, 8)) {
                p_route->origin = strndup(line+8, read-9);  // the same as PREFIX
            } else if (!strncmp("ASPATH: ", line, 8)) {
                s_tmp = line;
                p_route->as_path.length = 0;                // delimiter count
                while (*s_tmp) {
                    p_route->as_path.length += (*s_tmp++ == ' ');
                }
                p_route->as_path.asns = malloc(p_route->as_path.length * sizeof *p_route->as_path.asns);
                if (!p_route->as_path.asns) {
                    fprintf(stderr, "Malloc error for p_route->as_path.asns [%s]\n", __FUNCTION__);
                    exit(-1);
                }
                token = strtok_r(line, delimiter, &p_save);
                for (j = 0; j < p_route->as_path.length; j++) {
                    token = strtok_r(0, delimiter, &p_save);
                    p_route->as_path.asns[j] = atoi(token);
                }
            } else if (!strncmp("NEXT_HOP: ", line, 10)) {
                p_route->next_hop = strndup(line+10, read-11);
            } else if (!strncmp("COMMUNITY: ", line, 11)) {
                p_route->communities = strndup(line+11, read-12);
            } else if (!strncmp("ATOMIC_AGGREGATE", line, 16)) {
                p_route->atomic_aggregate = 1;
            } else if (!strncmp("MULTI_EXIT_DISC: ", line, 17)) {
                line[read-1] = 0;
                p_route->med = atoi(line+17);
            } else if (!strcmp("\n", line)) {
                HASH_FIND_STR(g_cfg.loaded_ribs[i], p_route->prefix, p_rib_entry);
                if (p_rib_entry) {
                    rl_add_route(&p_rib_entry->rl, tmp_asn, tmp_id, p_route, g_cfg.as_policies[i].selection_policy);
                } else {
                    p_rib_entry = malloc(sizeof *p_rib_entry);
                    if (!p_rib_entry) {
                        fprintf(stderr, "Malloc error for p_rib_entry [%s]\n", __FUNCTION__);
                        exit(-1);
                    }
                    p_rib_entry->key = strdup(p_route->prefix);
                    p_rib_entry->set = NULL;
                    p_rib_entry->rl = NULL;
                    rl_add_route(&p_rib_entry->rl, tmp_asn, tmp_id, p_route, g_cfg.as_policies[i].selection_policy);
                    HASH_ADD_KEYPTR(hh, g_cfg.loaded_ribs[i], p_rib_entry->key, strlen(p_rib_entry->key), p_rib_entry);
                }
                reset_route(p_route);
            }
        }
        fclose(fp);
    }
    free_route_ptr(&p_route);
    SAFE_FREE(line);
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
    printf("wsgx\n");
    route_process_w_sgx_init(&as_cfg, g_cfg.verbose);
#else
    printf("wosgx\n");
    route_process_wo_sgx_init(&as_cfg, g_cfg.verbose);
#endif
    efd = epoll_init();
    server_init(efd, as_cfg.as_size, &g_cfg.net);

    // run
    epoll_run(efd);

    return 0;
}
