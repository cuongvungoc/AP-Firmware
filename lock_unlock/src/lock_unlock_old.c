#include "dns_parser.h"

// state_alarm, 0 - unlock, 1 - lock
int state_alarm = 0;
int nslookup_trigger = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; // mutex init

int main(int argc, char *argv[])
{
    pthread_t thread_ID;
    int dns_parser_thread;

    // For get host by name
    // struct hostent *he;
    // struct in_addr **addr_list;

    // Option for lock or unlock
    char nslookup[CMD_SIZE] = "/usr/bin/nslookup ";
    char cmd[CMD_SIZE] = "sh /sbin/rule.sh ";
    char option[OPTION_SIZE];
    strcat(nslookup, URL);
    strcat(nslookup, NULL_SAVE);
    // char default_ip[CMD_SIZE] = "iptables -I white-list 1 -d ";

    // if (NULL == (he = gethostbyname(URL)))
    // {
    //     printf("Cannot get host by name\n");
    //     return 1;
    // }

    // addr_list = (struct in_addr **) he->h_addr_list;

    while (1)
    {
        if (UNLOCK_STATE == get_state_alarm())
        {
            printf("Enter lock to lock: ");
        }
        else
        {
            printf("Enter unlock to unlock: ");
        }

        scanf("%s", option);
        strcat(cmd, option);

        if (0 == strcmp(option, LOCK) && UNLOCK_STATE == get_state_alarm())
        {
            set_state_alarm(LOCK_STATE);
            system(cmd);
            dns_parser_thread = pthread_create(&thread_ID, NULL, dns_parser, NULL);
            if (dns_parser_thread)
            {
                printf("Pthread create error number = %d\n", dns_parser_thread);
                exit(1);
            }
            sleep(1);
            // nslookup for get default IP
            if (1 == nslookup_trigger)
            {
                system(nslookup);
            }
            // strcat(default_ip, inet_ntoa(*addr_list[0]));
            // strcat(default_ip, " -j ACCEPT");
            // system(default_ip);
            // strcpy(default_ip, "iptables -I white-list 1 -d ");
        }
        else if (0 == strcmp(option, UNLOCK) && LOCK_STATE == get_state_alarm())
        {
            set_state_alarm(UNLOCK_STATE);
            system(cmd);
            // pthread_cancel(thread_ID);
            pthread_join(thread_ID, NULL);
            usleep(1000);
        }
        else
        {
            printf("Invailid option!\n");
        }

        strcpy(cmd, "sh /sbin/rule.sh ");
    }

    pthread_exit(NULL);

    return 0;
}