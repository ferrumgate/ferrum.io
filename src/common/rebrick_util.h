#ifndef __REBRICK_UTIL_H__
#define __REBRICK_UTIL_H__
#include "rebrick_common.h"
#include "rebrick_log.h"
#include <sys/types.h>
#include <sys/time.h>



/**
    * @brief linked list structure and functions
    */
public_ typedef struct rebrick_linked_item
{
    base_object();
    public_ readonly_ unsigned char *data;
    public_ readonly_ size_t len;
    public_ readonly_ struct rebrick_linked_item *next;
    public_ readonly_ struct rebrick_linked_item *prev;
    public_ union {
        int val_int;
        short val_short;
        void *val_ext;

    } ext_data;

} rebrick_linked_item_t;

/**
     * @brief creates an  @see rebrick_linked_item_t
     * @param param1 sizeof array
     * @param param2 previous linked_item or NULL
     * @return NULL for error, or a valid address
     */
rebrick_linked_item_t *rebrick_util_linked_item_create(size_t len, rebrick_linked_item_t *previous);

/**
     * @brief destroys linked list from starting parameter to the end
     * @return returns previous item, it can also be NULL
     */
rebrick_linked_item_t *rebrick_util_linked_item_destroy(rebrick_linked_item_t *list);

/**
     * @brief counts the list
     * @returns items count
     */
size_t rebrick_util_linked_item_count(const rebrick_linked_item_t *list);

/**
    * @brief forwards list
    * @return forwarded position
    * @note if count is bigger than end than stops at end
    */
rebrick_linked_item_t *rebrick_util_linked_item_next(rebrick_linked_item_t *list, size_t count);

/**
    * @brief previouses list
    * @return previous position
    * @note if count is bigger than start than stops at start and returns start position
    */
rebrick_linked_item_t *rebrick_util_linked_item_prev(rebrick_linked_item_t *list, size_t count);
/**
    * @brief moves to start position
    */
rebrick_linked_item_t *rebrick_util_linked_item_start(rebrick_linked_item_t *list);

/**
     * @brief moves to end
     */
rebrick_linked_item_t *rebrick_util_linked_item_end(rebrick_linked_item_t *list);

/**
     * @brief creates a linked list from string with splitters
     * @return first position of linked list
     */
rebrick_linked_item_t *rebrick_util_create_linked_items(const char *str, const char *splitter);

/**
     * @brief creates a joined item
     * @return 0 for sucess,1 for error
     */
int rebrick_util_join_linked_items(const rebrick_linked_item_t *list, const char *splitter, char *dest, size_t destlen);

/**
    * @brief string ends with
    * @return  1 for success, 0 for not found
    */
int rebrick_util_str_endswith(const char *domainname, const char *search);

void rebrick_util_str_tolower(char *str);

//gets time in micro seconds
int64_t rebrick_util_micro_time();

//random
int rebrick_util_rand();

//gets current time
char *rebrick_util_time_r(char * str);


/**
 * @brief converts @see rebrick_sockaddr_t to ip string
 *
 * @param sock
 * @param buffer
 * @param len
 * @return int32_t
 */
int32_t rebrick_util_addr_to_ip_string(const rebrick_sockaddr_t *sock,char buffer[REBRICK_IP_STR_LEN]);

/**
 * @brief converts @see rebrick_sockaddr_t to port string
 *
 * @param sock
 * @param buffer
 * @param len
 * @return int32_t
 */
int32_t rebrick_util_addr_to_port_string(const rebrick_sockaddr_t *sock,char buffer[REBRICK_PORT_STR_LEN]);

/**
 * @brief convert a ip stirng and port to @rebrick_sockaddr_t
 *
 * @param sock
 * @param ip
 * @param port
 * @return int32_t
 */
int32_t rebrick_util_to_socket(rebrick_sockaddr_t *sock, const char *ip,const char*port);

int32_t rebrick_util_addr_to_roksit_addr(const struct sockaddr *addr, rebrick_sockaddr_t *sock);


int32_t rebrick_util_addr_to_rebrick_addr(const struct sockaddr *addr, rebrick_sockaddr_t *sock);



/**
 * @brief convert a ip stirng and port to @rebrick_sockaddr_t
 *
 * @param sock
 * @param ip
 * @param port
 * @return int32_t
 */
int32_t rebrick_util_ip_port_to_addr(const char *ip,const char*port,rebrick_sockaddr_t *sock);


/**
 * @brief compares ips
 *
 * @return 1 for equal otherwise 0
 */
int32_t rebrick_util_ip_equal(const rebrick_sockaddr_t *src,const rebrick_sockaddr_t *dst);

/**
 * @brief read all bytes from a file
 *
 * @param file
 * @param buffer will allocate buffer
 * @param len allocated size
 * @return int32_t
 */
int32_t rebrick_util_file_read_allbytes(const char *file,char **buffer,size_t *len);



#define string_to_lower(x) \
    char * _fakeptr=x;\
    while(*_fakeptr){ *_fakeptr=tolower(*_fakeptr);_fakeptr++; }







#endif // MACRO
