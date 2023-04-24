#include "dns_parser_daemon.h"

int is_exist(struct white_list_t *wlist, char *ip)
{
    int i = 0;

    if (0 == wlist->len)
        return 0;

    for (i = 0; i < wlist->len; i++)
    {
        if (0 == strcmp(wlist->ip_list[i], ip))
        {
            return 1;
            break;
        }
    }
    return 0;
}

void change_to_dns_name_format(char *dns, char *host)
{
    int i = 0, j = 0;
    int pos = 0;
    int len = strlen(host);
    char temp[len + 1];
    strcpy(temp, host);
    strcat(temp, ".");
    char temp2[len + 1];
    for (i = 0; i < len + 1; i++)
    {

        if (temp[i] == '.')
        {
            temp2[pos] = i - pos + 48;
            for (j = pos + 1; j <= i; j++)
            {
                temp2[j] = temp[j - 1];
            }
            pos = i + 1;
        }
    }
    temp2[pos] = '\0';
    strcpy(dns, temp2);
}

int compare_name_to_url(unsigned char *name, char *url, int len)
{
    int i = 0;
    char name_cmp[len];
    char url_cmp[len];
    strcpy(name_cmp, (char *)name);
    // Example: 6google3com, convert int to char
    for (i = 0; i < len; i++)
    {
        if (name_cmp[i] < 10 && name_cmp[i] != '\0')
        {
            name_cmp[i] += ZERO_CHAR;
        }
    }
    change_to_dns_name_format(url_cmp, url);
    return memcmp(name_cmp, url_cmp, len);
}

// Create a daemon process for DNS parser
void daemonize()
{
    pid_t pid;
    int i = 0; 
    int fd = 0;
    // Fork to create a new process
    pid = fork();

    if (pid < 0) 
    {
        fprintf(stderr, "Failed to fork child process\n");
        exit(1);
    }

    // If parent process, exit
    if (pid > 0) {
        exit(0);
    }

    // Set file mode mask
    umask(0);

    // Create a new session for the child process
    if (setsid() < 0) {
        fprintf(stderr, "Failed to create a new session for the child process\n");
        exit(1);
    }

    // Change the current working directory
    if (chdir("/") < 0) {
        fprintf(stderr, "Failed to change the current working directory\n");
        exit(1);
    }

    // Close all open file descriptors
    for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
        close(fd);
    }

    // Redirect stdin, stdout and stderr to /dev/null
    fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
    }
}

// Find domain name length in query section
int find_qname_len(unsigned char buffer[])
{
    int qlen = 0;
    // 192 - c0 (dns pointer, point to prev name)
    while (buffer[qlen] < 192)
    {
        qlen++;
    }
    return qlen - 2 * sizeof(unsigned short); // Query length - Type - Class
}

void add_to_whitelist(struct white_list_t *wlist, char* ip)
{
    char add_src[CMD_SIZE] = "iptables -I white_list 1 -s ";
    char add_des[CMD_SIZE] = "iptables -I white_list 1 -d ";
    if (0 == is_exist(wlist, ip)) // not exist
    {
        // Add IP to white_list
        strcpy(wlist->ip_list[wlist->len], ip);
        wlist->len += 1;

        // Add to chain and execute rule
        strcat(add_src, ip);
        strcat(add_src, " -j ACCEPT");
        system(add_src);
        strcpy(add_src, "iptables -I white_list 1 -s ");
        
        strcat(add_des, ip);
        strcat(add_des, " -j ACCEPT");
        system(add_des);
        strcpy(add_des, "iptables -I white_list 1 -d ");
    }
}