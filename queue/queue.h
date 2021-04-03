/**
 * @file queue.h
 * @author Nikos Fanourakis (4237)
 * @brief A queue library used for the correct cryptography of X and J characters
 * 
 */

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief A node representing a queue element
 * 
 */
struct node_t
{
  size_t position;
  struct node_t *next;
};

/**
 * @brief A node representing the whole queue
 * 
 */
struct queue_t
{
  unsigned int size;
  struct node_t *head;
  struct node_t *tail;
};

typedef struct node_t node_t;
typedef struct queue_t queue_t;

/**
 * @brief Initializes the queue
 * 
 * @return queue_t* A pointer to the memory allocated for the queue node
 */
queue_t *queue_init();

/**
 * @brief Checks if the queue is empty
 * 
 * @param q The queue node
 * @return int True when there are no nodes inside the queue
 */
int queue_is_empty(queue_t *q);

/**
 * @brief Adds an element to the end of the queue
 * 
 * @param q The queue pointer
 * @param position The value of position of the new element
 * @return int 0 for success, -1 for failure
 */
int enqueue(queue_t *q, size_t position);

/**
 * @brief Returns the value of the head queue element
 * 
 * @param q The queue pointer
 * @return size_t The value of the top element
 */
size_t queue_peek(queue_t *q);

/**
 * @brief Returns the value of the head queue element, removes it and frees the allocated memory
 * 
 * @param q The queue pointer
 * @return size_t The value of the head element removed
 */
size_t dequeue(queue_t *q);

/**
 * @brief Frees queue
 * 
 * @param q The queue pointer
 */
void queue_free(queue_t *q);