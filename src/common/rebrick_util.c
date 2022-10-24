#include "rebrick_util.h"

static int is_random_initialized = 0; // eğer random initialize edilmemiş ise init edit kullanacağım

int rebrick_util_str_endswith(const char *domainname, const char *search)
{
    if (domainname && search)
    {
        int len1 = strlen(domainname);
        int len2 = strlen(search);
        // eğer google.com icinde www.google.com
        if (len1 < len2)
            return 0;
        if (strncmp(&domainname[len1 - len2], search, len2) == 0)
            return 1;
    }
    return 0;
}

rebrick_linked_item_t *rebrick_util_linked_item_create(size_t len, rebrick_linked_item_t *previous)
{
    rebrick_linked_item_t *item = create(rebrick_linked_item_t);
    if (item == NULL)
        return NULL;
    fill_zero(item, sizeof(rebrick_linked_item_t));
    strcpy(item->type_name, "rebrick_linked_item_t");
    item->data = rebrick_malloc(len);
    if_is_null_then_die(item->data, "malloc problem\n");
    if (item->data == NULL)
    {
        rebrick_free(item);
        return NULL;
    }
    item->len = len;
    if (previous)
    {
        previous->next = item;
        item->prev = previous;
    }

    return item;
}

/*
 * @brief item ve sonraki elemenları siler
 * @return kendinden önceki elemanı döner
 */
rebrick_linked_item_t *rebrick_util_linked_item_destroy(rebrick_linked_item_t *item)
{
    if (item == NULL)
        return NULL;
    rebrick_linked_item_t *previous = item->prev;
    if (item->next)
    {
        rebrick_util_linked_item_destroy(item->next);
        item->next = NULL;
    }
    if (item->data)
    {
        rebrick_free(item->data);
        item->data = NULL;
    }
    if (item->prev)
        item->prev->next = NULL;
    rebrick_free(item);
    return previous;
}

size_t rebrick_util_linked_item_count(const rebrick_linked_item_t *item)
{
    size_t count = 0;
    if (item == NULL)
        return count;
    do
    {
        count++;
    } while ((item = item->next));
    return count;
}
rebrick_linked_item_t *rebrick_util_linked_item_next(rebrick_linked_item_t *item, size_t count)
{
    while (count && item)
    {
        item = item->next;
        count--;
    }
    return item;
}
rebrick_linked_item_t *rebrick_util_linked_item_prev(rebrick_linked_item_t *item, size_t count)
{

    while (count && item)
    {
        item = item->prev;
        count--;
    }
    return item;
}

rebrick_linked_item_t *rebrick_util_linked_item_start(rebrick_linked_item_t *item)
{
    while (item)
    {
        if (item->prev == NULL)
            break;
        item = item->prev;
    }
    return item;
}

rebrick_linked_item_t *rebrick_util_linked_item_end(rebrick_linked_item_t *item)
{

    while (item)
    {
        if (item->next == NULL)
            break;
        item = item->next;
    }
    return item;
}

rebrick_linked_item_t *rebrick_util_create_linked_items(const char *str, const char *splitter)
{
    char *split;
    size_t len;
    char *data;
    char *saveptr;
    rebrick_linked_item_t *start = NULL, *current = NULL, *temp;

    if (str == NULL)
        return NULL;

    len = strlen(str) + 1;

    if (len == 1)
        return NULL;

    data = rebrick_malloc(len);
    if_is_null_then_die(data, "malloc problem\n");
    if (data == NULL)
        return NULL;

    strcpy(data, str);
    split = strtok_r(data, splitter, &saveptr);
    while (split)
    {
        len = strlen(split) + 1;
        temp = rebrick_util_linked_item_create(len, current);
        if (temp == NULL)
        {
            if (start != NULL)
                rebrick_util_linked_item_destroy(start);

            rebrick_free(data);
            return NULL;
        }

        strcpy((char *)temp->data, split);
        temp->len = len;
        if (start == NULL)
        {
            start = temp;
        }
        current = temp;
        split = strtok_r(NULL, splitter, &saveptr);
    }
    rebrick_free(data);
    return start;
}

// 0 success,1 error
int rebrick_util_join_linked_items(const rebrick_linked_item_t *list, const char *splitter, char *dest, size_t destlen)
{
    size_t splitlength;
    if (!list || !splitter || !dest || !destlen)
        return 1;

    fill_zero(dest, destlen);
    splitlength = strlen(splitter);

    destlen -= strlen((const char *)list->data);
    if (destlen < 1)
        return 1;

    strcpy(dest, (const char *)list->data);

    list = list->next;
    while (list)
    {
        destlen -= strlen((const char *)list->data) + splitlength;
        if (destlen < 1)
            return 1;

        strcat(dest, splitter);
        strcat(dest, (const char *)list->data);
        list = list->next;
    }
    return 0;
}

void rebrick_util_str_tolower(char *str)
{
    unsigned char *p = (unsigned char *)str;

    for (; *p; p++)
        *p = tolower(*p);
}

int64_t rebrick_util_micro_time()
{
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return currentTime.tv_sec * (int64_t)1e6 + currentTime.tv_usec;
}

// random
int rebrick_util_rand()
{
    if (!is_random_initialized)
    {
        is_random_initialized = 1;
        srand(time(NULL));
    }
    return rand();
}

//////////region//////rand16//////////start/////////////

static uint32_t seed[32];
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x, b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i, b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x, b));

static void surf(void)
{
    uint32_t t[12];
    uint32_t x;
    uint32_t sum = 0;
    int r;
    int i;
    int loop;

    for (i = 0; i < 12; ++i)
        t[i] = in[i] ^ seed[12 + i];
    for (i = 0; i < 8; ++i)
        out[i] = seed[24 + i];
    x = t[11];
    for (loop = 0; loop < 2; ++loop)
    {
        for (r = 0; r < 16; ++r)
        {
            sum += 0x9e3779b9;
            MUSH(0, 5)
            MUSH(1, 7)
            MUSH(2, 9)
            MUSH(3, 13)
            MUSH(4, 5)
            MUSH(5, 7)
            MUSH(6, 9)
            MUSH(7, 13)
            MUSH(8, 5)
            MUSH(9, 7)
            MUSH(10, 9)
            MUSH(11, 13)
        }
        for (i = 0; i < 8; ++i)
            out[i] ^= t[i + 4];
    }
}
static int32_t is_initialized16 = 0;
static void random16_init()
{
    if (is_random_initialized == 0)
    {
        srand(time(NULL));
        is_random_initialized = 1;
    }
    for (unsigned int i = 0; i < sizeof(seed); i += sizeof(int))
    {
        int r = rand();
        unsigned char *ptr = cast(&seed, unsigned char *);
        memcpy(ptr + i, &r, sizeof(int));
    }
    for (unsigned int i = 0; i < sizeof(int); i += sizeof(int))
    {
        int r = rand();
        unsigned char *ptr = cast(&seed, unsigned char *);
        memcpy(ptr + i, &r, sizeof(int));
    }
}

uint16_t rebrick_util_rand16()
{
    if (!is_initialized16)
    {
        random16_init();
    }

    if (!outleft)
    {
        if (!++in[0])
            if (!++in[1])
                if (!++in[2])
                    ++in[3];
        surf();
        outleft = 8;
    }

    return out[--outleft];
}

//////////region////////rand16////////stop///////////////

char *rebrick_util_time_r(char *str)
{
    time_t current_time = time(NULL);
    ctime_r(&current_time, str);
    // remove \n
    str[strlen(str) - 1] = 0;
    return str;
}

int32_t rebrick_util_addr_to_rebrick_addr(const struct sockaddr *addr, rebrick_sockaddr_t *sock)
{

    if (addr->sa_family == AF_INET)
    {
        memcpy(&sock->v4, addr, sizeof(struct sockaddr_in));
    }
    if (addr->sa_family == AF_INET6)
    {
        memcpy(&sock->v6, addr, sizeof(struct sockaddr_in6));
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_addr_to_ip_string(const rebrick_sockaddr_t *sock, char buffer[REBRICK_IP_STR_LEN])
{
    if (sock->base.sa_family == AF_INET)
    {

        uv_ip4_name(&sock->v4, buffer, 16);
    }
    if (sock->base.sa_family == AF_INET6)
    {

        uv_ip6_name(&sock->v6, buffer, 45);
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_addr_to_port_string(const rebrick_sockaddr_t *sock, char buffer[REBRICK_PORT_STR_LEN])
{

    if (sock->base.sa_family == AF_INET)
    {

        sprintf(buffer, "%d", ntohs(sock->v4.sin_port));
    }
    if (sock->base.sa_family == AF_INET6)
    {

        sprintf(buffer, "%d", ntohs(sock->v6.sin6_port));
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_to_rebrick_sockaddr(rebrick_sockaddr_t *sock, const char *ip, const char *port)
{

    if (uv_ip6_addr(ip, atoi(port), cast(&sock->v6, struct sockaddr_in6 *)) < 0)
    {

        if (uv_ip4_addr(ip, atoi(port), cast(&sock->v4, struct sockaddr_in *)) < 0)
        {

            return REBRICK_ERR_BAD_IP_PORT_ARGUMENT;
        }
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_ip_port_to_addr(const char *ip, const char *port, rebrick_sockaddr_t *sock)
{
    fill_zero(sock, sizeof(rebrick_sockaddr_t));
    if (uv_ip6_addr(ip, atoi(port), cast(&sock->v6, struct sockaddr_in6 *)) < 0)
    {

        if (uv_ip4_addr(ip, atoi(port), cast(&sock->v4, struct sockaddr_in *)) < 0)
        {

            return REBRICK_ERR_BAD_IP_PORT_ARGUMENT;
        }
    }
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_file_read_allbytes(const char *file, char **buffer, size_t *len)
{

    char current_time_str[32] = {0};
    unused(current_time_str);
    FILE *fileptr;
    int64_t filelen;
    fileptr = fopen(file, "rb");
    if (!fileptr)
        return REBRICK_ERR_BAD_ARGUMENT;
    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);
    char *temp = rebrick_malloc(filelen + 1);
    if_is_null_then_die(temp, "malloc problem\n");

    fill_zero(temp, filelen + 1);
    fread(temp, filelen, 1, fileptr);
    fclose(fileptr);
    *buffer = temp;
    *len = filelen;
    return REBRICK_SUCCESS;
}

int32_t rebrick_util_ip_equal(const rebrick_sockaddr_t *src, const rebrick_sockaddr_t *dst)
{
    if (!src || !dst)
        return 0;
    if (src->base.sa_family == AF_INET)
        return memcmp(&src->v4.sin_addr, &dst->v4.sin_addr, sizeof(struct in_addr)) == 0 ? 1 : 0;
    return memcmp(&src->v6.sin6_addr, &dst->v6.sin6_addr, sizeof(struct in6_addr)) == 0 ? 1 : 0;
}
