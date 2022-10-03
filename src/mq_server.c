/*
 * server.c: Server program
 *           to demonstrate interprocess commnuication
 *           with POSIX message queues
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ldb.h>
#include <string.h>
#include <sys/types.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#define SERVER_QUEUE_NAME   "/scanoss-api"
#define CLIENT_QUEUE_NAME   "/scanoss-engine"
#define QUEUE_PERMISSIONS 0660
#define MAX_MESSAGES 10
#define MAX_MSG_SIZE 1024 * 64
#define MSG_BUFFER_SIZE MAX_MSG_SIZE + 10

 mqd_t qd_server, qd_client;   // queue descriptors

static int wfp_scan(char * path)
{
	char * line = NULL;
	size_t len = 0;
	ssize_t lineln;
	uint8_t *rec = NULL;
	FILE *fp = stdin;
	char *tmp_md5_hex = NULL;
	char * buffer = calloc(MSG_BUFFER_SIZE, 1);
	/* Open WFP file */
	if (path)
	{
		fp = fopen(path, "r");
		if (fp == NULL)
		{
			fprintf(stdout, "E017 Cannot open target");
			return EXIT_FAILURE;
		}
	}
	
	bool is_end = true;

	/* Read line by line */
	while ((lineln = getline(&line, &len, fp)) != -1)
	{
		if (lineln < 0)
			continue;

		bool is_file = (memcmp(line, "file=", 5) == 0);
		/* Parse file information with format: file=MD5(32),file_size,file_path */
		if (is_file)
		{
			if (strlen(buffer))
			{
				if (mq_send (qd_client, buffer, strlen (buffer) + 1, 0) == -1) 
				{
            		perror ("Server: Not able to send message to client");
        		}
			
				printf("%s\n----------------", buffer);
				memset(buffer, 0, MSG_BUFFER_SIZE);
			}
			strcat(buffer, line);
		}
		else
		{
			strcat(buffer, line);
		}

	}
	/* Scan the last file */
	//send las file
	if (mq_send (qd_client, buffer, strlen (buffer) + 1, 0) == -1) 
	{
    	perror ("Server: Not able to send message to client");
    }
			
	printf("%s\n---END---------", buffer);

	if (path)
		fclose(fp);
		
	if (line) free(line);
	
	free(buffer);
	return EXIT_SUCCESS;
}


int main (int argc, char **argv)
{
    long token_number = 1; // next token to be given to client

    printf ("Server: Hello, World!\n");

    struct mq_attr attr;

    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;

    if ((qd_server = mq_open (SERVER_QUEUE_NAME, O_RDONLY | O_CREAT, QUEUE_PERMISSIONS, &attr)) == -1) {
        perror ("Server: mq_open (server)");
        exit (1);
    }

 	if ((qd_client = mq_open (CLIENT_QUEUE_NAME, O_WRONLY | O_CREAT, QUEUE_PERMISSIONS, &attr)) == -1) {
        perror ("Client: mq_open (client)");
        exit (1);
    }


    char in_buffer [MSG_BUFFER_SIZE];
    char out_buffer [MSG_BUFFER_SIZE];
	char *path = argv[argc-1];

	wfp_scan(path);
/*
    while (1) {
        // get the oldest message with highest priority
        if (mq_receive (qd_server, in_buffer, MSG_BUFFER_SIZE, NULL) == -1) {
            perror ("Server: mq_receive");
            exit (1);
        }

        printf ("Server: message received.\n");

        // send reply message to client

        if ((qd_client = mq_open (in_buffer, O_WRONLY)) == 1) {
            perror ("Server: Not able to open client queue");
            continue;
        }

        sprintf (out_buffer, "%ld", token_number);



        printf ("Server: response sent to client.\n");
        token_number++;
    }*/
}