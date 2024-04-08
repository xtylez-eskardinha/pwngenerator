#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 54471
#define MAX_EVENTS 100

struct Event
{
    char name[50];
    char location[50];
    char date[50];
    char time[50];
};

struct Event events[MAX_EVENTS];
int num_events = 0;
int new_socket;

void execme()
{
    FILE *flagfile;
    char flag[256];

    flagfile = fopen("/flag/flag.txt", "r");
    fscanf(flagfile, "%s", flag);

    send(new_socket, flag, strlen(flag), 0);
}

void add_event(int socket, char *name, char *location, char *date, char *time)
{
    char buffer[1024];
    if (name && location && date && time)
    {
        if (num_events < MAX_EVENTS)
        {
            strcpy(events[num_events].name, name);
            strcpy(events[num_events].location, location);
            strcpy(events[num_events].date, date);
            strcpy(events[num_events].time, time);
            sprintf(buffer, "Event added to the agenda\n");
            num_events++;
            send(socket, buffer, strlen(buffer), 0);
        }
        else
        {
            send(socket, "Error: Agenda is full.\n", 26, 0);
        }
    }
    else
    {
        send(socket, "Error: Invalid command syntax.\n", 31, 0);
    }
}

void list_events(int socket)
{
    char event_list[1024] = "";
    for (int i = 0; i < num_events; i++)
    {
        char event[1024];
        sprintf(event, "Event %d:\nName: %s\nLocation: %s\nDate: %s\nTime: %s\n\n",
                i + 1, events[i].name, events[i].location, events[i].date, events[i].time);
        strcat(event_list, event);
    }
    send(socket, event_list, strlen(event_list), 0);
}

void display_help(int socket)
{
    char *help_message = "Commands:\nadd <name> <location> <date> <time> - Add an event to the agenda\nlist - List all events in the agenda\nhelp - Display this help message\n";
    send(socket, help_message, strlen(help_message), 0);
}

int main(int argc, char const *argv[])
{
    int server_fd, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Welcome to the agenda server!\nEnter 'help' for a list of commands.\n";

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 54471
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port 54471
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        new_socket = accept(server_fd, (struct sockaddr *) &address, (struct socklen_t *) &addrlen);
        if (new_socket < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if (fork() == 0)
        {

            // Send welcome message
            send(new_socket, hello, strlen(hello), 0);

            while (1)
            {
                memset(buffer, 0, 1024);
                valread = read(new_socket, buffer, 1024);
                if (valread == 0)
                {
                    printf("Client disconnected\n");
                    break;
                }
                else if (valread < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }

                // Process command
                char *command = strtok(buffer, " ");
                if (strcmp(command, "add") == 0)
                {
                    char *name = strtok(NULL, " ");
                    char *location = strtok(NULL, " ");
                    char *date = strtok(NULL, " ");
                    char *time = strtok(NULL, " ");
                    add_event(new_socket, name, location, date, time);
                }
                else if (strcmp(command, "list\n") == 0)
                {
                    list_events(new_socket);
                }
                else if (strcmp(command, "help\n") == 0)
                {
                    display_help(new_socket);
                }
            }
        }
    }
}