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
    char *as_conf_file;
    int verbose;
} cfg = {{NULL, 0, NULL, 0}, NULL};

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
        "   -a, --as_conf_file FILE     specify an as configuration file to get as policies, default is conf/as.conf"
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
        {"as_conf_file", required_argument, NULL, 'a'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
            case 'h':
                print_help();
                exit(0);

            case 'b':
                cfg.net.bgp_serv_addr = optarg;
                break;

            case 'p':
                cfg.net.bgp_serv_port = atoi(optarg);

            case 'c':
                cfg.net.pctrlr_serv_addr = optarg;
                break;

            case 't':
                cfg.net.pctrlr_serv_port = atoi(optarg);
                break;

            case 'v':
                cfg.verbose = atoi(optarg);
                break;

            case 'a':
                if (access(optarg, F_OK) == -1) {
                    perror(optarg);
                    exit(-1);
                } else {
                    cfg.as_conf_file = optarg;
                    break;
                }

            default:
                print_help();
                exit(-1);
        }
    }

    return;
}

static void load_as_conf(uint32_t *p_total_num, as_policy_t **pp_as_policies)
{
    uint32_t i, j, r;
    int fscanf_ret;
    assert(p_total_num != NULL && pp_as_policies != NULL);
    FILE *fp;

    if ((fp = fopen(cfg.as_conf_file, "r")) == NULL) {
        fprintf(stderr, "can not open file: %s [%s]\n", cfg.as_conf_file, __FUNCTION__);
        exit(-1);
    }

    if (fscanf(fp, "%u\n", p_total_num) != 1) {
        fprintf(stderr, "illegal total_num and edge_num format [%s]\n", __FUNCTION__);
        exit(-1);
    }

    *pp_as_policies = malloc(*p_total_num * sizeof **pp_as_policies);
    if (!*pp_as_policies) {
        fprintf(stderr, "Malloc error for pp_as_policies [%s]\n", __FUNCTION__);
        return;
    }

    for (i = 0; i < *p_total_num; i++) {
        (*pp_as_policies)[i].asn = i;
        (*pp_as_policies)[i].total_num = *p_total_num;

        // import_policy
        // 0: me, 1: customer, 2: peer, 3: provider, N: no conn
        (*pp_as_policies)[i].import_policy = malloc(*p_total_num * sizeof *(*pp_as_policies)[i].import_policy);
        for (j = 0; j < *p_total_num; j++) {
            (*pp_as_policies)[i].import_policy[j] = *p_total_num;
        }
        (*pp_as_policies)[i].import_policy[i] = 0;

        // export_policy[N * N] represents policy[N][N]
        // policy[p][q] means if AS i would like to export prefixes
        //      with next_hop p to AS q
        //      0: do not export, 1: export
        // for each AS, export all routes to customers
        //              export customer and its own routes to all others
        (*pp_as_policies)[i].export_policy = malloc(*p_total_num * *p_total_num * sizeof *(*pp_as_policies)[i].export_policy);
        for (j = 0; j < *p_total_num * *p_total_num; j++) {
            (*pp_as_policies)[i].export_policy[j] = 0;
        }
    }

    uint32_t *tmp_customers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t *tmp_peers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t *tmp_providers = malloc(*p_total_num * sizeof(uint32_t));
    uint32_t customer_num = 0, peer_num = 0, provider_num = 0;
    for (i = 0; i < *p_total_num; i++) {
        fscanf_ret = fscanf(fp, "%u", &customer_num);
        assert(fscanf_ret == 1);
        for (j = 0; j < customer_num; j++) {
            fscanf_ret = fscanf(fp, " %u", &tmp_customers[j]);
            assert(fscanf_ret == 1);
            (*pp_as_policies)[i].import_policy[tmp_customers[j]] = 1;
        }
        fscanf_ret = fscanf(fp, "\n");
        assert(fscanf_ret == 0);
        fscanf_ret = fscanf(fp, "%u", &peer_num);
        assert(fscanf_ret == 1);
        for (j = 0; j < peer_num; j++) {
            fscanf_ret = fscanf(fp, " %u", &tmp_peers[j]);
            assert(fscanf_ret == 1);
            (*pp_as_policies)[i].import_policy[tmp_peers[j]] = 2;
        }
        fscanf_ret = fscanf(fp, "\n");
        assert(fscanf_ret == 0);
        fscanf_ret = fscanf(fp, "%u", &provider_num);
        assert(fscanf_ret == 1);
        for (j = 0; j < provider_num; j++) {
            fscanf_ret = fscanf(fp, " %u", &tmp_providers[j]);
            assert(fscanf_ret == 1);
            (*pp_as_policies)[i].import_policy[tmp_providers[j]] = 3;
        }
        fscanf_ret = fscanf(fp, "\n");
        assert(fscanf_ret == 0);

        // export_policy
        for (j = 0; j < customer_num; j++) {
            for (r = 0; r < *p_total_num; r++) {
                (*pp_as_policies)[i].export_policy[tmp_customers[j] + r * *p_total_num] = 1;
            }
            for (r = 0; r < peer_num; r++) {
                (*pp_as_policies)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_peers[r]] = 1;
            }
            for (r = 0; r < provider_num; r++) {
                (*pp_as_policies)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_providers[r]] = 1;
            }
            (*pp_as_policies)[i].export_policy[tmp_customers[j] * *p_total_num + tmp_customers[j]] = 0;
        }
        for (r = 0; r < peer_num; r++) {
            (*pp_as_policies)[i].export_policy[i * *p_total_num + tmp_peers[r]] = 1;
        }
        for (r = 0; r < provider_num; r++) {
            (*pp_as_policies)[i].export_policy[i * *p_total_num + tmp_providers[r]] = 1;
        }
    }

    if (cfg.verbose == 5) {
        for (i = 0; i < *p_total_num; i++) {
            printf("AS %u import_policy:\n", i);
            for (j = 0; j < *p_total_num; j++) {
                printf("%u ", (*pp_as_policies)[i].import_policy[j]);
            }
            printf("\n");
        }
        printf("\n");
        for (i = 0; i < *p_total_num; i++) {
            printf("AS %u export_policy:\n", i);
            for (j = 0; j < *p_total_num; j++) {
                for (r = 0; r < *p_total_num; r++) {
                    printf("%u ", (*pp_as_policies)[i].export_policy[r + j * *p_total_num]);
                }
                printf("\n");
            }
            printf("\n");
        }
    }
}

int main(int argc, char *argv[])
{
    int efd;
    uint32_t as_num;
    as_policy_t *p_as_policies = NULL;

    parse_args(argc, argv);
    if (!cfg.net.bgp_serv_addr) cfg.net.bgp_serv_addr = "127.0.0.1";
    if (!cfg.net.bgp_serv_port) cfg.net.bgp_serv_port = 6000;
    if (!cfg.net.pctrlr_serv_addr) cfg.net.pctrlr_serv_addr = "127.0.0.1";
    if (!cfg.net.pctrlr_serv_port) cfg.net.pctrlr_serv_port = 6666;
    if (!cfg.as_conf_file) cfg.as_conf_file = AS_CONF_FILE;

    // initialization
    load_as_conf(&as_num, &p_as_policies);
#ifdef W_SGX
    printf("wsgx\n");
    route_process_w_sgx_init(as_num, &p_as_policies);
#else
    printf("wosgx\n");
    route_process_wo_sgx_init(as_num, &p_as_policies);
#endif
    efd = epoll_init();
    server_init(efd, as_num, &cfg.net);

    // run
    epoll_run(efd);

    return 0;
}
