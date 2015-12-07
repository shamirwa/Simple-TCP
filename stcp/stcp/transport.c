/*
* transport.c 
*
* CS536 PA2 (Reliable Transport)
*
* This file implements the STCP layer that sits between the
* mysocket and network layers. You are required to fill in the STCP
* functionality in this file. 
*
*/


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

enum { 
	CSTATE_DEFAULT = 0,
	CSTATE_SYNSENT = 1,
	CSTATE_SYNRCVD = 2,
	CSTATE_SYNACKSENT = 3,
	CSTATE_SYNACKRCVD = 4,
	CSTATE_ACKSENT = 5,
	CSTATE_ACKRCVD = 6,
	CSTATE_ESTABLISHED = 7,
	CSTATE_FINWAIT_1 = 8,
	CSTATE_FINWAIT_2 = 9,
        CSTATE_CLOSE_WAIT = 10,
        CSTATE_LAST_ACK = 11,
        CSTATE_CLOSING = 12,
	CSTATE_TIME_WAIT = 13
};    /* obviously you should have more states */

//Uncommented this line to enable the printf statements
//#define print 1
#define MAX_WINDOW_SIZE 3072
#define TCP_HEADER_SIZE 20
#define SEQUENCE_NUMBER_SPACE 4294967296
#define TCP_DATA_OFFSET 5
#define MAX_RETRIES 6

/* this structure is global to a mysocket descriptor */
typedef struct
{
	bool_t done;    /* TRUE once connection is closed */

	int connection_state;   /* state of the connection (established, etc.) */
	tcp_seq initial_sequence_num;

	// Sequence Number Info After HandShake
	tcp_seq remote_sequence_num; // Next Data Packet will contain ACK Flag for this sequence number

	// Receiver Information
	int rcvrWindow[MAX_WINDOW_SIZE]; /* Bytes in receiver bufer which have been stored and acked for inorder delivery */
	tcp_seq expectedSeqNumber;       /* Expected Sequence number at remote side */
	tcp_seq rcvBufferBaseInfo;       /* Receiver buffer base information of local side */
	tcp_seq selfRcvWindowSize;       /* Receiver window size of local side */
	tcp_seq currentRcvrWindowSize;   /* Receiver window size of remote side */

	// Sender information 
	int sndrWindow[MAX_WINDOW_SIZE]; 
	tcp_seq sendBase;
	tcp_seq nextSeqNum;
	tcp_seq sendBufferBaseInfo;
	bool isTimerSet;
	int numberOfRetransmission;


	// Buffer to store the Rcvd and Snd Data
	char rcvrDataBuffer[MAX_WINDOW_SIZE]; /* Receiver Buffer of local side */
	char sndrDataBuffer[MAX_WINDOW_SIZE]; /* Sender Buffer of local side */

	mysocket_t sd;

	// Retransmission count of FIN
	int finRetransmit;

} context_t;

// Global declaration of Context variable for accessing in timer related
// functions
static context_t *ctx;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
void stopTimer();
void startTimer();
void createStcpHeader(STCPHeader* stcpHdr);
// Function to set the timer variable
void setTimerForUnackedData(bool value)
{
	#ifdef print
	printf("\n setTimerForUnackedData Method Entry\n");
	#endif
	ctx->isTimerSet = value;
}

//Function to check whether timer is set or not
bool isTimerValueSet(){
	#ifdef print
        printf("\n isTimerValueSet Method Entry\n");
	#endif
	return ctx->isTimerSet;
}

//Function to handle the timer expiry by retransmission
void handleTimerExpiry(int sigNum)
{
	#ifdef print
	printf("\n HandleTimeExpiry Method Entry\n");
	#endif
	size_t retransmitDataLength = 0, stcpSegmentLength = 0;
	char* dataToRetransmit = NULL;
	unsigned int iterator = 0, iterator2 = 0, numOfSegments = 0;
	tcp_seq startSeqNumber = ctx->sendBase;
	char* stcpSegment = NULL;
	STCPHeader *segmentHeader = NULL;

	if(isTimerValueSet())
	     stopTimer();


	if((ctx->numberOfRetransmission < MAX_RETRIES) && (ctx->connection_state == CSTATE_ESTABLISHED)){

	  // Check the length of packet that needs to be retransmitted
	  if(ctx->nextSeqNum > ctx->sendBase){
			retransmitDataLength = ctx->nextSeqNum - ctx->sendBase;
	  }
	  else if(ctx->nextSeqNum < ctx->sendBase){
			retransmitDataLength = ctx->nextSeqNum + (SEQUENCE_NUMBER_SPACE - ctx->sendBase + 1);
	  }

	  // Check the number of segments that needs to be send
	  numOfSegments = (int)(retransmitDataLength/STCP_MSS);

	  if((numOfSegments*STCP_MSS) < retransmitDataLength){
			numOfSegments++;
	  }

	  // Copy the data into the buffer
	  dataToRetransmit = (char*) calloc(retransmitDataLength, sizeof(char));

	  iterator2 = ctx->sendBufferBaseInfo;

	  for(iterator = 0; iterator < retransmitDataLength; iterator++){
			dataToRetransmit[iterator] = ctx->sndrDataBuffer[iterator2];
			iterator2 = (iterator2 + 1) % MAX_WINDOW_SIZE;
	  }

	  // Make segments and send the packet to the remote side
	  do{  
			if(retransmitDataLength >= STCP_MSS){
				stcpSegmentLength = TCP_HEADER_SIZE + STCP_MSS;
				stcpSegment = (char*) calloc(stcpSegmentLength, sizeof(char));
				segmentHeader = (STCPHeader*) stcpSegment;

				createStcpHeader(segmentHeader);

				memcpy(stcpSegment+TCP_HEADER_SIZE, dataToRetransmit, STCP_MSS);
			
				#ifdef print
				printf("\n Retransmitted segment count %d\n",ctx->numberOfRetransmission);
				#endif

				dataToRetransmit = dataToRetransmit + STCP_MSS;
				retransmitDataLength = retransmitDataLength - STCP_MSS;

				segmentHeader->th_seq = htonl(startSeqNumber);
				startSeqNumber = startSeqNumber + STCP_MSS;
			}
			else{

				stcpSegmentLength = TCP_HEADER_SIZE + retransmitDataLength;
				stcpSegment = (char*) calloc(stcpSegmentLength, sizeof(char));
				segmentHeader = (STCPHeader*) stcpSegment;

				createStcpHeader(segmentHeader);

				memcpy(stcpSegment+TCP_HEADER_SIZE, dataToRetransmit, retransmitDataLength);
				segmentHeader->th_seq = htonl(startSeqNumber);
				retransmitDataLength = 0;
			}

			do{
			}while(stcp_network_send(ctx->sd, stcpSegment, stcpSegmentLength, NULL) < 0);

		        numOfSegments--;

			if(stcpSegment){
				free(stcpSegment);
				stcpSegment = NULL;
			}
		}while(retransmitDataLength != 0 || numOfSegments != 0);  
	  
		ctx->numberOfRetransmission++;
	}
	else if((ctx->finRetransmit < MAX_RETRIES) && (ctx->connection_state == CSTATE_FINWAIT_1)){

	   	// Allocate memory for FIN Packet
	   	segmentHeader = (STCPHeader*) calloc(1, sizeof(STCPHeader));
	   	// Create the Header
		segmentHeader->th_seq = htonl(ctx->nextSeqNum - 1);
		segmentHeader->th_off = TCP_DATA_OFFSET;
		segmentHeader->th_win = htons(ctx->selfRcvWindowSize);
	   	segmentHeader->th_flags = 0|TH_FIN;

	   	//send the FIN Packet
	   	while(stcp_network_send(ctx->sd, segmentHeader, sizeof(STCPHeader), NULL) < 0){
           	}

	   	// Change the state to FIN_WAIT_1
	   	ctx->connection_state = CSTATE_FINWAIT_1;
		ctx->finRetransmit++;

		#ifdef print
		printf("\n FIN RETRANSMIT COUNT %d",ctx->finRetransmit);
		#endif
        }
	else if((ctx->finRetransmit < MAX_RETRIES) && (ctx->connection_state == CSTATE_LAST_ACK)){
       		// Create the FIN Packet
		segmentHeader = (STCPHeader*) calloc(1, sizeof(STCPHeader));
                // Create the Header
		segmentHeader->th_seq = htonl(ctx->nextSeqNum - 1);
		segmentHeader->th_off = TCP_DATA_OFFSET;
		segmentHeader->th_win = htons(ctx->selfRcvWindowSize);
		segmentHeader->th_flags = 0|TH_FIN;
		
		//send the FIN Packet
		while(stcp_network_send(ctx->sd, segmentHeader, sizeof(STCPHeader), NULL) < 0){
		}

		// Change the state to LAST_ACK
		ctx->connection_state = CSTATE_LAST_ACK;
		#ifdef print
		printf("\n FIN RETRANSMIT COUNT %d",ctx->finRetransmit);
		#endif
		ctx->finRetransmit++;
       	}else{
		#ifdef print
       		printf("\n Network Layer has failed after trying to retransmit the packet for 6 times\n");
		#endif
		ctx->done = true;
		exit(0);
        }

	if(!isTimerValueSet())
	        startTimer();

}

//Function to start timer (Timer value is chosen as 500ms)
void startTimer(){
	#ifdef print
	printf("\n startTime method entry\n");
	#endif
	setTimerForUnackedData(true);
	signal(SIGALRM, handleTimerExpiry);
	alarm(1);
}

// Function to stop the timer
void stopTimer(){
	#ifdef print
	printf("\nstop timer method entry\n");
	#endif
	setTimerForUnackedData(false);
	alarm(0);
}


// Function to create the packet header 
void createStcpHeader(STCPHeader* stcpHdr){
	  #ifdef print
	  printf("\ncreateStcpHeader Method Entry\n");
          #endif
	  if(stcpHdr != NULL){
		 stcpHdr->th_seq = htonl(ctx->nextSeqNum);
		 stcpHdr->th_off = TCP_DATA_OFFSET;
		 stcpHdr->th_win = htons(ctx->selfRcvWindowSize);
	  }
	  else{
		 #ifdef print
		 printf("Error in createStcpHeader\n");
		 #endif
	  }
}

// Function to get the data size that can be stored 
tcp_seq getEmptySenderBufferSize(){
		 
	// NextSeq number has completed one cycle
	if((ctx->nextSeqNum < ctx->sendBase) && (SEQUENCE_NUMBER_SPACE - ctx->sendBase + 1) < MAX_WINDOW_SIZE)
	{
		 return (MAX_WINDOW_SIZE - (SEQUENCE_NUMBER_SPACE - ctx->sendBase + ctx->nextSeqNum +1));
	}
	else
	{
		return (MAX_WINDOW_SIZE - ctx->nextSeqNum + ctx->sendBase);
	}
}

// Function to store the data inside the sender or receiver buffer 
void storeDataIntoBuffer(char* dataBuffer, char* sentBuffer, size_t indexToStart, size_t lengthOfData){

 #ifdef print
 printf("\n storeDataIntoBuffer Method Entry\n");
 #endif
 unsigned int iterator1;
 unsigned int iterator2 = indexToStart;

 for(iterator1 = 0; iterator1 < lengthOfData; iterator1++){
	dataBuffer[iterator2] = sentBuffer[iterator1];
	iterator2 = (iterator2+1)%MAX_WINDOW_SIZE;  // We need to make sure that the last pointer in send Buffer 
											// doesn't cross the maximum window size.
	}
}

// Function to set the index for received bytes in receiver buffer 
void setReceivedBytesInReceiverWindow(int* rcvrWindow, size_t startPosition, size_t totalLength){
	#ifdef print
	printf("\n setReceivedBytesInReceiverWindow  Method Entry\n");
	#endif
	unsigned int iterator = startPosition;
	unsigned int iterator2;
	for(iterator2 = 0;iterator2 < totalLength; iterator2++){
		rcvrWindow[iterator] = 1;
		iterator = (iterator + 1)%MAX_WINDOW_SIZE;
	}
}

// Function which sends the data to the application 
void sendDataToApplication(mysocket_t sd){
  
   #ifdef print
   printf("\n SendDataToApplication Method Entry\n");
   #endif
   unsigned int lengthOfDataToSent = 0;
   unsigned int iterator =  ctx->rcvBufferBaseInfo;
   unsigned int iterator2 = 0;
   char* dataToApp = NULL;

   while(ctx->rcvrWindow[iterator] == 1 && lengthOfDataToSent < MAX_WINDOW_SIZE){
		lengthOfDataToSent++;
		iterator = (iterator + 1)%MAX_WINDOW_SIZE;
   }

   if(lengthOfDataToSent > MAX_WINDOW_SIZE){
		lengthOfDataToSent = MAX_WINDOW_SIZE;
   }
   
   //create the buffer to store data to send to application
   dataToApp = (char*) calloc(lengthOfDataToSent, sizeof(char));

   //copy the data from receiver window
   iterator = ctx->rcvBufferBaseInfo;
   for(iterator2 = 0; iterator2<lengthOfDataToSent; iterator2++)
   {
	  dataToApp[iterator2] = ctx->rcvrDataBuffer[iterator];
	  ctx->rcvrWindow[iterator] = -1;
	  iterator = (iterator + 1)%MAX_WINDOW_SIZE;
   }

   //send data to App
   stcp_app_send(sd, dataToApp, lengthOfDataToSent);
   
   if(dataToApp != NULL){
		free(dataToApp);
		dataToApp = NULL;
   }

   //Update the varibales
   ctx->expectedSeqNumber = ctx->expectedSeqNumber + lengthOfDataToSent;
   ctx->rcvBufferBaseInfo = (ctx->rcvBufferBaseInfo + lengthOfDataToSent) % MAX_WINDOW_SIZE;

   // Be sure that the receiver window size doesn't go beyond MAX_WINDOW_SIZE
   ctx->selfRcvWindowSize = MIN(ctx->selfRcvWindowSize + lengthOfDataToSent, MAX_WINDOW_SIZE);

}

// Function to send the Acknowledgement
void sendAcknowledgementPacket(mysocket_t sd){

   // Create the Ack Packet
   STCPHeader *stcpAckPacket = NULL;

   stcpAckPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
   createStcpHeader(stcpAckPacket);
  
   stcpAckPacket->th_ack = htonl(ctx->expectedSeqNumber);
   stcpAckPacket->th_flags = 0|TH_ACK;
   while(stcp_network_send(ctx->sd, stcpAckPacket, sizeof(STCPHeader), NULL) < 0){
   }
   #ifdef print
   printf("\n Sending ACK for seq number %u\n",ctx->expectedSeqNumber);
   #endif
}

/* initialise the transport layer, and start the main loop, handling
* any data from the peer or the application.  this function should not
* return until the connection is closed.
*/
void transport_init(mysocket_t sd, bool_t is_active)
{
	ssize_t recvdDataLength = 0;
	unsigned int rcvdEvent = 0;
	tcp_seq remoteSeqNumber;
	tcp_seq localSeqNumber;
	int success = 0;
	int retries = 0;

	time_t timeToTimeout;
	timeToTimeout = time(NULL);
	timeToTimeout = timeToTimeout + 2;

	struct timespec waitTime;
	waitTime.tv_sec = timeToTimeout;

	// Control packet pointer
	STCPHeader* stcpPacket = NULL;


	ctx = (context_t *) calloc(1, sizeof(context_t));
	assert(ctx);

	ctx->done = false;
	ctx->connection_state = CSTATE_DEFAULT;

	// Generate the initial Sequence Number
	generate_initial_seq_num(ctx);
	localSeqNumber = ctx->initial_sequence_num;

	/* XXX: you should send a SYN packet here if is_active, or wait for one
	* to arrive if !is_active.  after the handshake completes, unblock the
	* application with stcp_unblock_application(sd).  you may also use
	* this to communicate an error condition back to the application, e.g.
	* if connection fails; to do so, just set errno appropriately (e.g. to
	* ECONNREFUSED, etc.) before calling the function.
	*/

	if(is_active)
	{
		while(success == 0 && retries < MAX_RETRIES)
		{
			// Allocate memory of header size to send the SYN Packet
			stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));

			// Creating a SYN packet 
			stcpPacket->th_flags = 0 | TH_SYN;
			stcpPacket->th_seq = htonl(localSeqNumber++);
			stcpPacket->th_off = 0;
			stcpPacket->th_win = htons(MAX_WINDOW_SIZE);
			stcpPacket->th_ack = htonl(0);

			// SYN packet sent
			if(stcp_network_send(sd, stcpPacket, sizeof(STCPHeader), NULL) < 0){
				#ifdef print
				printf("\nFailed to send the SYN packet \n");
				#endif
				errno = ECONNREFUSED;
			}
			else{
				#ifdef print
				printf("SYN Packet Sent %d\n",stcpPacket->th_seq);
				#endif
				//Connection State Changed to SYN SENT
				ctx->connection_state = CSTATE_SYNSENT;
				free(stcpPacket);
				stcpPacket = NULL;
			}// End of SYN

			// Wait for SYN-ACK to be received for infinite time period (Need to implement a timeout mechanism)
			rcvdEvent = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, &waitTime);
			stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
			assert(stcpPacket);

			if(rcvdEvent & NETWORK_DATA){

				if((recvdDataLength = stcp_network_recv(sd, stcpPacket, sizeof(STCPHeader))) < 0){
					#ifdef print
					printf("\n SYN-ACK packet of size 0 received from the Network\n");
					#endif
				}
				else{
					#ifdef print
					printf("\n Received the Packet from Network Layer after sending SYN\n");
					#endif

					stcpPacket = (STCPHeader *)(stcpPacket);
					stcpPacket->th_ack = ntohl(stcpPacket->th_ack);
					stcpPacket->th_seq = ntohl(stcpPacket->th_seq);

					#ifdef print
					printf("\n Sequence Number of SYNACK Packet is %d, ACK %d",stcpPacket->th_seq, stcpPacket->th_ack);
					#endif
					if((stcpPacket->th_flags & TH_SYN) && (stcpPacket->th_flags & TH_ACK) &&
						(stcpPacket->th_ack == (localSeqNumber))){

						#ifdef print
						printf("\n SYN-ACK packet received from the server\n");
						#endif
						success = 1;
						remoteSeqNumber = stcpPacket->th_seq;

						//Connection State Changed to SYN-ACK RCVD
						ctx->connection_state = CSTATE_SYNACKRCVD;
						free(stcpPacket);
						stcpPacket = NULL; // End of SYN-ACK

						//Creating an ACK packet
						stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
						assert(stcpPacket);

						stcpPacket->th_flags = 0 | TH_ACK;
						stcpPacket->th_seq = htonl(localSeqNumber++);
						stcpPacket->th_off = 0;
						stcpPacket->th_win = htons(MAX_WINDOW_SIZE);
						stcpPacket->th_ack = htonl(++remoteSeqNumber);

						if(stcp_network_send(sd, stcpPacket, sizeof(STCPHeader), NULL) < 0){
							#ifdef print	
							printf("\nFailed to send the ACK packet \n");
							#endif
							errno = ECONNREFUSED;
						}
						else{
							#ifdef print
							printf("\n ACK packet sent successfully with seq number %d\n", stcpPacket->th_seq);
							#endif
							//Connection State Changed to ACK SENT
							ctx->connection_state = CSTATE_ACKSENT;
							free(stcpPacket);
							stcpPacket = NULL;
						}
					}else{
							#ifdef print
							printf("\n Wrong SYN-ACK packet received\n");
							#endif
							retries++;
					}
				}            
			}else if(rcvdEvent == TIMEOUT){
				#ifdef print
				printf("\n Timeout of SYN Packet. Retransmitting SYN Packet \n");
				#endif
				retries++;
			}
		}
	}
	else
	{
		// Server Side 
		// - Waiting for the SYN Packet to be received
		rcvdEvent = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

		// Allocating memory to receive buffer
		stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
		assert(stcpPacket);

		if(rcvdEvent & NETWORK_DATA)
		{
			if((recvdDataLength = stcp_network_recv(sd, stcpPacket, sizeof(STCPHeader))) < 0){
				#ifdef print
				printf("\n SYN packet of size 0 received from the Network\n");
				#endif
			}
			else{
				#ifdef print
				printf("\n Received a Packet from Network Layer\n");
				#endif

				stcpPacket = (STCPHeader *)(stcpPacket);
				stcpPacket->th_seq = ntohl(stcpPacket->th_seq);

				if(stcpPacket->th_flags & TH_SYN){
					#ifdef print
					printf("\n SYN packet received from the client with seqNum %d\n",stcpPacket->th_seq);
					#endif
					//Connection State Changed to SYNRCVD
					ctx->connection_state = CSTATE_SYNRCVD;
					remoteSeqNumber = stcpPacket->th_seq;
					free(stcpPacket);
					stcpPacket = NULL;

					while( retries < MAX_RETRIES && success == 0)
					{
						//Building the SYN-ACK Packet to send
						stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
						assert(stcpPacket);

						stcpPacket->th_flags = (0 | TH_ACK | TH_SYN);
						stcpPacket->th_seq = htonl(localSeqNumber++);
						stcpPacket->th_off = 0;
						stcpPacket->th_win = htons(MAX_WINDOW_SIZE);
						stcpPacket->th_ack = htonl(++remoteSeqNumber);

						// Sending the SYN-ACK Packet
						if(stcp_network_send(sd, stcpPacket, sizeof(STCPHeader), NULL) < 0){
							#ifdef print
							printf("\nFailed to send the SYN-ACK packet \n");
							#endif
							errno = ECONNREFUSED;
						}else
						{
							#ifdef print
							printf("SYN-ACK sent with Seq Number %d",stcpPacket->th_seq);
							#endif
							//Connection State Changed to SYNACKSENT
							ctx->connection_state = CSTATE_SYNACKSENT;
							free(stcpPacket);
							stcpPacket = NULL;
						} // End of SYN-ACK PACKET

						//Wait for ACK packet
						rcvdEvent = stcp_wait_for_event(sd, NETWORK_DATA | TIMEOUT, &waitTime);
						stcpPacket = (STCPHeader*) calloc(1, sizeof(STCPHeader));
						assert(stcpPacket);

						if(rcvdEvent & NETWORK_DATA){

							if((recvdDataLength = stcp_network_recv(sd, stcpPacket, sizeof(STCPHeader))) < 0){
								#ifdef print
								printf("\n ACK packet of size 0 received from the Network\n");
								#endif
							}
							else{
								#ifdef print
								printf("\n Received the ACK Packet from Network Layer after sending SYN-ACK\n");
								#endif

								stcpPacket = (STCPHeader *)(stcpPacket);
								stcpPacket->th_ack = ntohl(stcpPacket->th_ack);
								stcpPacket->th_seq = ntohl(stcpPacket->th_seq);

								if((stcpPacket->th_flags & TH_ACK) && 
									stcpPacket->th_ack == (localSeqNumber)){
						
									success = 1;
									#ifdef print
									printf("\n ACK packet received from the client with Seq Number %d in seq field and %d in ack field \n",stcpPacket->th_seq,stcpPacket->th_ack);
									#endif
									remoteSeqNumber = stcpPacket->th_seq + 1;

									//Connection State Changed to ACK RCVD
									ctx->connection_state = CSTATE_ACKRCVD;
									free(stcpPacket);
									stcpPacket = NULL;
								}
								else{
									#ifdef print
									printf("\nWrong Ack Packet Received\n");
									#endif
									retries++;
								}
							}
						}else if(rcvdEvent & TIMEOUT){
							#ifdef print
							printf("\n Timeout happened for SYN-ACK Packet\n");
							#endif
							retries++;
						}
					}
				}
			}
		}
	}        

	if(success == 1){
		ctx->connection_state = CSTATE_ESTABLISHED;
		ctx->initial_sequence_num = localSeqNumber;
		ctx->remote_sequence_num = remoteSeqNumber;
		stcp_unblock_application(sd);

		control_loop(sd, ctx);
	}else{
		ctx->done = true;
	}

	/* do any cleanup here */
	if(stcpPacket != NULL){
		free(stcpPacket);
	}
	free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
	assert(ctx);

	#ifdef FIXED_INITNUM
	/* please don't change this! */
	ctx->initial_sequence_num = 1;
	#else
	/* you have to fill this up 
	   Will generate a random initial sequence number within 0-255*/
	ctx->initial_sequence_num = rand() % 256;
	#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
* following to happen:
*   - incoming data from the peer
*   - new data from the application (via mywrite())
*   - the socket to be closed (via myclose())
*   - a timeout
*/
static void control_loop(mysocket_t sd, context_t *ctx)
{
	char *rcvdAppData = NULL, *rcvdNetworkData = NULL;
	size_t rcvdAppDataLength = 0, rcvdNetworkDataLength = 0;
	int iterator = 0;
	unsigned int numOfPacket, event;

	//Max data bytes sender buffer can receive from APP
	size_t maxAppDataRcvdLength = 0;
	size_t startIndex = 0;

	// STCP Segment
	char* stcpSegment = NULL;

	// STCP Header
	STCPHeader* segmentHeader = NULL;
	STCPHeader* ackSegment = NULL;
	size_t stcpSegmentLength = 0;

	assert(ctx);

	//setting the sender Window Informations
	ctx->sendBase = ctx->initial_sequence_num;
	ctx->nextSeqNum = ctx->initial_sequence_num;
	ctx->sendBufferBaseInfo = 0;
	ctx->numberOfRetransmission = 0;
	ctx->finRetransmit = 0;
	setTimerForUnackedData(false);


	//Setting the receiver related Informations
	ctx->expectedSeqNumber = ctx->remote_sequence_num;
	ctx->rcvBufferBaseInfo = 0;
	ctx->currentRcvrWindowSize = MAX_WINDOW_SIZE;
	ctx->selfRcvWindowSize = MAX_WINDOW_SIZE;

	// Setting the socket descriptor inside the context structure
	ctx->sd = sd;

	for(;iterator < MAX_WINDOW_SIZE; iterator++){
		ctx->rcvrWindow[iterator] = -1;
	}

	while (!ctx->done)
	{
		/* see stcp_api.h or stcp_api.c for details of this function */
		/* XXX: you will need to change some of these arguments! */
		if(getEmptySenderBufferSize() == 0){
			event = stcp_wait_for_event(sd, NETWORK_DATA | APP_CLOSE_REQUESTED | TIMEOUT, NULL); 
		}
		else{
			event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
		}
		/* check whether it was the network, app, or a close request */

		// NETWORK DATA Received
		if(event & NETWORK_DATA){
			// Receive the segment from the network layer
			stcpSegmentLength = TCP_HEADER_SIZE + STCP_MSS; /* Maximum Data sender can send is MSS i.e. 536*/
			stcpSegment = (char*) calloc(stcpSegmentLength, sizeof(char));

			// Update the segment length with the length of the data received 
			stcpSegmentLength = stcp_network_recv(sd, stcpSegment, stcpSegmentLength);

			segmentHeader = (STCPHeader*) stcpSegment;
			// Endianess Support
			segmentHeader->th_ack = ntohl(segmentHeader->th_ack);
			segmentHeader->th_seq = ntohl(segmentHeader->th_seq);
			segmentHeader->th_win = ntohs(segmentHeader->th_win);

			ctx->currentRcvrWindowSize = (segmentHeader->th_win); /* storing the remote side receiver window */

			/* Here we will first see whether there is any data in tha packet or its just an ACK packet
			* for data packet we need to send the ACK ASAP */

			if(TCP_OPTIONS_LEN(stcpSegment) == 0){
				rcvdNetworkDataLength = stcpSegmentLength - TCP_HEADER_SIZE; // There is no options in segment
			}else{
				rcvdNetworkDataLength = stcpSegmentLength - TCP_OPTIONS_LEN(stcpSegment) - TCP_HEADER_SIZE;
			}

			// This will handle DATA Packet with or without ACK 
			if(rcvdNetworkDataLength != 0){

				// Handle the ACK packet and DATA Packet separately
				// Here we will update the sequence numbers as per the ACK received
				if(segmentHeader->th_flags & TH_ACK){
					if(segmentHeader->th_ack > ctx->sendBase && 
						segmentHeader->th_ack <= ctx->nextSeqNum)
					{

						#ifdef print
						printf("\n Data packet with valid ACK packet received with seq number %u and seq number of ack field %u\n", segmentHeader->th_seq,segmentHeader->th_ack);
						#endif
						ctx->sendBufferBaseInfo = (ctx->sendBufferBaseInfo + (segmentHeader->th_ack - ctx->sendBase)) % MAX_WINDOW_SIZE;
						ctx->sendBase = segmentHeader->th_ack;
						// Timer Check, if running then stop it`
						if(isTimerValueSet()){
							stopTimer();
						}
						// Restart the time if there are still some unacked data
						if(ctx->sendBase < ctx->nextSeqNum){
							startTimer();
						}
					}	
				}//Handle the DATA Packet along with FIN packet
				if((segmentHeader->th_flags & TH_FIN) &&
	                                        (segmentHeader->th_seq == ctx->expectedSeqNumber)) {

						if(ctx->connection_state == CSTATE_ESTABLISHED){
	                                                // Notify the application
                                                        stcp_fin_received(sd);
                                                        // Change the state to CLOSE_WAIT
                                                        ctx->connection_state = CSTATE_CLOSE_WAIT;
                                                                                                                                                                                         }
                                                 else if(ctx->connection_state == CSTATE_FINWAIT_1){
                                                        // Notify the application       
                                                        stcp_fin_received(sd);
                                                                                                                                                                                                //Change the state to CLOSING
                                                        ctx->connection_state = CSTATE_CLOSING;
                                                                                                                                                                                         }else if(ctx->connection_state == CSTATE_FINWAIT_2){
                                                        // Notify the application
                                                        stcp_fin_received(sd);
                                                                                                                                                                                                // Change state to TIME_WAIT
                                                        ctx->connection_state = CSTATE_TIME_WAIT;
							printf("\n BYE BYE -- M GOING DOWN \n");
                                                        ctx->done = true;
							exit(0);
						}
				}
				#ifdef print
				printf("\n DAta packet received with sequence number %u\n",segmentHeader->th_seq);
				#endif
	
				// check whether the segment is inorder (Receiver's Action)
				if(segmentHeader->th_seq == ctx->expectedSeqNumber){

					#ifdef print
					printf("\n In Order Data Received\n");
					#endif
					if(rcvdNetworkDataLength > MAX_WINDOW_SIZE){
						rcvdNetworkDataLength = MAX_WINDOW_SIZE;
					}
	   
					rcvdNetworkData = (char*) calloc(rcvdNetworkDataLength, sizeof(char));
					memcpy(rcvdNetworkData, stcpSegment+TCP_DATA_START(stcpSegment), rcvdNetworkDataLength);

					// store the received data into the receiver data buffer
					storeDataIntoBuffer(ctx->rcvrDataBuffer, rcvdNetworkData, 
					ctx->rcvBufferBaseInfo, rcvdNetworkDataLength);

					// switch the bytes on in receiver window which have been received
					setReceivedBytesInReceiverWindow(ctx->rcvrWindow, ctx->rcvBufferBaseInfo, rcvdNetworkDataLength);

					// Send Data to Application 
					sendDataToApplication(sd);

					//Send Ack for the inorder data received
					sendAcknowledgementPacket(sd);
		   
					// Free the memory after storing it inside the receiver buffer
					if(rcvdNetworkData != NULL){
						free(rcvdNetworkData);
						rcvdNetworkData = NULL;
					}
				}
				//Received the out of order data (Receiver Action)
				else if(segmentHeader->th_seq > ctx->expectedSeqNumber && 
						segmentHeader->th_seq <= (ctx->expectedSeqNumber + MAX_WINDOW_SIZE -1)){
						#ifdef print
						printf("\n Out of Order Data received\n");
						#endif
				
						// check for the buffer space in receivers end. Space should be there
						// as we are sending the data from sender side only if rcvr window size
						// is greater than 0. To be double sure we can check here again
						if(ctx->selfRcvWindowSize > 0){
							//check for data size is within the window size or not
							if((segmentHeader->th_seq + rcvdNetworkDataLength) > 
										(ctx->expectedSeqNumber + MAX_WINDOW_SIZE - 1)){
								rcvdNetworkDataLength = (ctx->expectedSeqNumber + MAX_WINDOW_SIZE - segmentHeader->th_seq);
							} 
							
							rcvdNetworkData = (char*) calloc(rcvdNetworkDataLength, sizeof(char));
							memcpy(rcvdNetworkData, stcpSegment+TCP_DATA_START(stcpSegment), rcvdNetworkDataLength);

							startIndex = (ctx->rcvBufferBaseInfo + (segmentHeader->th_seq - ctx->expectedSeqNumber))%MAX_WINDOW_SIZE;
								

							storeDataIntoBuffer(ctx->rcvrDataBuffer, rcvdNetworkData, startIndex, rcvdNetworkDataLength);
								

							//switch the bytes on in receiver window which have been received
							setReceivedBytesInReceiverWindow(ctx->rcvrWindow, startIndex, rcvdNetworkDataLength);
	
							//Update the receiver window size 
							ctx->selfRcvWindowSize = ctx->selfRcvWindowSize - rcvdNetworkDataLength;

							//Send Acknowledgement	
							sendAcknowledgementPacket(sd);

							//Free the memory after storing it insider the receiver buffer
							if(rcvdNetworkData != NULL){
								free(rcvdNetworkData);
								rcvdNetworkData = NULL;
							}
						}
				}
				// Data Received contains part of old data and part of expected data (Receiver Action)
				else if(segmentHeader->th_seq < ctx->expectedSeqNumber && 
				                           segmentHeader->th_seq >= ctx->expectedSeqNumber - MAX_WINDOW_SIZE){

					// Discard the Data which is already acknowledged
					if((segmentHeader->th_seq + rcvdNetworkDataLength) >= ctx->expectedSeqNumber){
					// This means data has part of new data also. Need to store that and send to application
					        #ifdef print
						printf("\n Old Segment received may contain some new data\n");
						#endif
						// Data Start Position in packet
						startIndex = ctx->expectedSeqNumber - segmentHeader->th_seq;
					
						rcvdNetworkDataLength = (rcvdNetworkDataLength - (ctx->expectedSeqNumber - segmentHeader->th_seq));

						if(rcvdNetworkDataLength > MAX_WINDOW_SIZE){
							rcvdNetworkDataLength = MAX_WINDOW_SIZE;
					        }

						//Copy the required portion of data from the segment
						rcvdNetworkData = (char*) calloc(rcvdNetworkDataLength, sizeof(char));
						memcpy(rcvdNetworkData, stcpSegment+TCP_DATA_START(stcpSegment)+startIndex, rcvdNetworkDataLength);

						// store the received data into the receiver data buffer
						storeDataIntoBuffer(ctx->rcvrDataBuffer, rcvdNetworkData,
						ctx->rcvBufferBaseInfo, rcvdNetworkDataLength);

						// switch the bytes on in receiver window which have been received
						setReceivedBytesInReceiverWindow(ctx->rcvrWindow, ctx->rcvBufferBaseInfo, rcvdNetworkDataLength);

						// Send Data to Application 
						sendDataToApplication(sd);

						//Send Ack for the inorder data received
						sendAcknowledgementPacket(sd);

						// Free the memory after storing it inside the receiver buffer
						if(rcvdNetworkData != NULL){
							free(rcvdNetworkData);
							rcvdNetworkData = NULL;
						}
					}else
						sendAcknowledgementPacket(sd);
				}
			}
			// PURE ACK PACKET RECEIVED
			else if( rcvdNetworkDataLength == 0){
				// Received the ACK packet (Sender Action)
				if(segmentHeader->th_flags & TH_ACK){
					if(ctx->connection_state == CSTATE_ESTABLISHED){
						if(segmentHeader->th_ack > ctx->sendBase && segmentHeader->th_ack <= ctx->nextSeqNum)
						{
							#ifdef print
							printf("\n Ack packet received with seq number %u and seq number of ack field %u\n", segmentHeader->th_seq,segmentHeader->th_ack);
							#endif
							ctx->sendBufferBaseInfo = (ctx->sendBufferBaseInfo + (segmentHeader->th_ack - ctx->sendBase)) % MAX_WINDOW_SIZE;
							ctx->sendBase = segmentHeader->th_ack;
						
					        	// Timer Check, if running then stop it`
							if(isTimerValueSet()){
								stopTimer();
							}
							// Restart the time if there are still some unacked data
							if(ctx->sendBase < ctx->nextSeqNum){
								startTimer();
							}
                                                        // ACK received for INORDER Data
							ctx->numberOfRetransmission = 0;
						
						}else{
							#ifdef print
							printf("\n ACK Packet with sequence number out of congestion window\n");
							#endif
						}
					}else if(ctx->connection_state == CSTATE_FINWAIT_1){
						// change the state and send nothing
						ctx->connection_state = CSTATE_FINWAIT_2;
						ctx->finRetransmit = 0;

						if(isTimerValueSet()){
						   stopTimer();
						}
					}else if(ctx->connection_state == CSTATE_LAST_ACK){
					        ctx->finRetransmit = 0;	
                                                ctx->connection_state = CSTATE_TIME_WAIT;
						if(isTimerValueSet()){
						    stopTimer();
						}
						// change the state and send nothing
						printf("\n BYE BYE -- M GOING DOWN \n");
                                                ctx->done = true;
						exit(0);

					}else if(ctx->connection_state == CSTATE_CLOSING){
						// change the state to time_wait
						ctx->connection_state = CSTATE_TIME_WAIT;
						ctx->finRetransmit = 0;

						 if(isTimerValueSet()){
						     stopTimer();
						 }
					}
				   
				}// Received a FIN segment
				else if((segmentHeader->th_flags & TH_FIN) && 
				        (segmentHeader->th_seq == ctx->expectedSeqNumber)) {

					if(ctx->connection_state == CSTATE_ESTABLISHED){
					        // Notify the application
						stcp_fin_received(sd);
						// Send the ACK packet
						ackSegment = (STCPHeader*) calloc(1, sizeof(STCPHeader));
						createStcpHeader(ackSegment);

						ackSegment->th_ack = htonl(++(ctx->expectedSeqNumber));
						ackSegment->th_flags = 0|TH_ACK;

						while(stcp_network_send(sd, ackSegment, sizeof(STCPHeader), NULL) < 0){
						}

						// Change the state to CLOSE_WAIT
						ctx->connection_state = CSTATE_CLOSE_WAIT;
					
					        // free the memory
						if( ackSegment != NULL){
						        free(ackSegment);
							ackSegment = NULL;
					        }
					}
					else if(ctx->connection_state == CSTATE_FINWAIT_1){
				                // Notify the application	
						stcp_fin_received(sd);

						// Send the Ack
						ackSegment = (STCPHeader*) calloc(1, sizeof(STCPHeader));
                                                createStcpHeader(ackSegment);
                                                ackSegment->th_ack = htonl(++(ctx->expectedSeqNumber));
				                ackSegment->th_flags = 0|TH_ACK;

                                                while(stcp_network_send(sd, ackSegment, sizeof(STCPHeader), NULL) < 0){
                                                }
						//Change the state to CLOSING
						ctx->connection_state = CSTATE_CLOSING;

					}else if(ctx->connection_state == CSTATE_FINWAIT_2){
						// Notify the application
						stcp_fin_received(sd);
						// Send the ACK Packet
                                                ackSegment = (STCPHeader*) calloc(1, sizeof(STCPHeader));
                                                createStcpHeader(ackSegment);
                                                ackSegment->th_ack = htonl(++(ctx->expectedSeqNumber));
				                ackSegment->th_flags = 0|TH_ACK;

				                while(stcp_network_send(sd, ackSegment, sizeof(STCPHeader), NULL) < 0){
	                                        }

						// Change state to TIME_WAIT
						ctx->connection_state = CSTATE_TIME_WAIT;
						printf("\n BYE BYE -- M GOING DOWN \n");
						ctx->done = true;
						exit(0);
					}
				}				
			}
	
		        if(segmentHeader != NULL){
				segmentHeader = NULL;
			}
			if(stcpSegment != NULL){
				free(stcpSegment);
				stcpSegment = NULL;
			}
		}
		// Application is sending the DATA 
		else if (event & APP_DATA)
		{
			/* the application has requested that data be sent */
			/* see stcp_app_recv() */
			#ifdef print
			printf("\nApplication Data Event Fired\n"); 
			#endif
			// Check the empty space in sender buffer
			maxAppDataRcvdLength  = getEmptySenderBufferSize();

			//  Checking the receiver window size with the empty data buffer
			maxAppDataRcvdLength = MIN(maxAppDataRcvdLength, ctx->currentRcvrWindowSize);

			// Again wait for event if the buffer on sender side is full
			if(maxAppDataRcvdLength <= 0){
				continue;
			}
			// Allocate memory to receive the data
			rcvdAppData = (char*) calloc(maxAppDataRcvdLength, sizeof(char));

			// Get the data from application
			
		        rcvdAppDataLength = stcp_app_recv(sd, rcvdAppData, maxAppDataRcvdLength);
			

			// Buffer the received data
			startIndex  = (ctx->sendBufferBaseInfo + (ctx->nextSeqNum - ctx->sendBase)) % MAX_WINDOW_SIZE;
			storeDataIntoBuffer(ctx->sndrDataBuffer, rcvdAppData, startIndex, rcvdAppDataLength);

			numOfPacket = (int)(rcvdAppDataLength/STCP_MSS);

			if(numOfPacket*STCP_MSS < rcvdAppDataLength){
				++numOfPacket;
			}

			// Send data received from the Applicaiton to the receiver 
			do{
				// Allocate memory to the segment
				if(rcvdAppDataLength >= STCP_MSS){

					stcpSegmentLength = TCP_HEADER_SIZE + STCP_MSS;
					stcpSegment = (char*) calloc(stcpSegmentLength, sizeof(char));

					segmentHeader = (STCPHeader*) stcpSegment;
					//Fill the header
					createStcpHeader(segmentHeader);

					//copy the data inside the segment
					memcpy(stcpSegment+TCP_HEADER_SIZE, rcvdAppData, STCP_MSS);

					// Update the data information from app side
					rcvdAppData = rcvdAppData + STCP_MSS;
					rcvdAppDataLength = rcvdAppDataLength - STCP_MSS;

					//Update the next sequence number
					ctx->nextSeqNum = ctx->nextSeqNum + STCP_MSS;
				}
				else
				{

					stcpSegmentLength = TCP_HEADER_SIZE + rcvdAppDataLength;
					stcpSegment = (char*) calloc(stcpSegmentLength, sizeof(char));
					segmentHeader = (STCPHeader*) stcpSegment;

					//Fill the header
					createStcpHeader(segmentHeader);

					//copy the data inside the segment
					memcpy(stcpSegment+TCP_HEADER_SIZE, rcvdAppData, rcvdAppDataLength);

					// Update the next sequence number
					ctx->nextSeqNum = ctx->nextSeqNum + rcvdAppDataLength;
					rcvdAppDataLength = 0;
				}

				// Keep on sending till it successfully sents the segment
				do{
				}while(stcp_network_send(sd, stcpSegment, stcpSegmentLength, NULL) < 0);

				numOfPacket--;

				//Packet has been sent release the memory
				if(stcpSegment){
					free(stcpSegment);
					stcpSegment = NULL;
				}
			}while(rcvdAppDataLength != 0 || numOfPacket != 0);  // End of Data Send

			// Data has been sent start the timer and set the count to 1
			if(isTimerValueSet()){
			       stopTimer();
				startTimer();
			}else{
				startTimer();
			}

		}
		// Application is requesting to close the connection
		else if(event & APP_CLOSE_REQUESTED){
			#ifdef print
			printf("\n APP CLOSED EVENT FIRED\n");
			#endif
		   
			//Create the FIN Packet
			if(ctx->connection_state == CSTATE_ESTABLISHED){
				segmentHeader = (STCPHeader*) calloc(1, sizeof(STCPHeader));
				createStcpHeader(segmentHeader);
				segmentHeader->th_flags = 0|TH_FIN;
		        
				// Send the FIN Packet
				while(stcp_network_send(ctx->sd, segmentHeader, sizeof(STCPHeader), NULL) < 0){
				}
				
				// Change the state to FIN_WAIT_1
				ctx->connection_state = CSTATE_FINWAIT_1;
				ctx->nextSeqNum++;
			}
			else if(ctx->connection_state == CSTATE_CLOSE_WAIT){

				segmentHeader = (STCPHeader*) calloc(1, sizeof(STCPHeader));
			        createStcpHeader(segmentHeader);
				segmentHeader->th_flags = 0|TH_FIN;

				//send the FIN Packet
				while(stcp_network_send(ctx->sd, segmentHeader, sizeof(STCPHeader), NULL) < 0){
                                }
                                // Change the state to LAST_ACK
                                ctx->connection_state = CSTATE_LAST_ACK;
				ctx->nextSeqNum++;
			}
                          // Timer set for FIN packet
                         if(isTimerValueSet()){
		            stopTimer();
		            startTimer();
		        }else{
		            startTimer();
		        }

			if(segmentHeader != NULL){
				free(segmentHeader);
				segmentHeader = NULL;
			}
						   
		}
		else if(event & TIMEOUT){
			#ifdef print
			printf("\n TIMEOUT EVENT FIRED\n");
			#endif
			continue;

		}
	}
}

/**********************************************************************/
/* our_dprintf
*
* Send a formatted message to stdout.
* 
* format               A printf-style format string.
*
* This function is equivalent to a printf, but may be
* changed to log errors to a file if desired.
*
* Calls to this function are generated by the dprintf amd
* dperror macros in transport.h
*/
void our_dprintf(const char *format,...)
{
	va_list argptr;
	char buffer[1024];

	assert(format);
	va_start(argptr, format);
	vsnprintf(buffer, sizeof(buffer), format, argptr);
	va_end(argptr);
	fputs(buffer, stdout);
	fflush(stdout);
}
