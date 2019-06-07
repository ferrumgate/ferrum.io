#include "rebrick_util.h"

static int is_random_initialized = 0; //eğer random initialize edilmemiş ise init edit kullanacağım

int rebrick_util_str_endswith(const char *domainname, const char *search)
{
    if (domainname && search)
    {
        int len1 = strlen(domainname);
        int len2 = strlen(search);
        //eğer google.com icinde www.google.com
        if (len1 < len2)
            return 0;
        if (strncmp(&domainname[len1 - len2], search, len2) == 0)
            return 1;
    }
    return 0;
}

rebrick_linked_item_t *rebrick_util_linked_item_create(size_t len, rebrick_linked_item_t *previous)
{
    rebrick_linked_item_t *item = new(rebrick_linked_item_t);
    if (item == NULL)
        return NULL;
    fill_zero(item, sizeof(rebrick_linked_item_t));
    strcpy(item->type_name, "rebrick_linked_item_t");
    item->data = malloc(len);
    if (item->data == NULL)
    {
        free(item);
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
        free(item->data);
        item->data = NULL;
    }
    if (item->prev)
        item->prev->next = NULL;
    free(item);
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

    data = malloc(len);
    if (data == NULL)
        return NULL;

    strcpy(data, str);
    split = strtok_r(data, splitter,&saveptr);
    while (split)
    {
        len = strlen(split) + 1;
        temp = rebrick_util_linked_item_create(len, current);
        if (temp == NULL)
        {
            if (start != NULL)
                rebrick_util_linked_item_destroy(start);

            free(data);
            return NULL;
        }

        strcpy((char *)temp->data, split);
        temp->len = len;
        if (start == NULL)
        {
            start = temp;
        }
        current = temp;
        split = strtok_r(NULL, splitter,&saveptr);
    }
    free(data);
    return start;
}

//0 success,1 error
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

//random
int rebrick_util_rand()
{
    if (!is_random_initialized)
    {
        is_random_initialized = 1;
        srand(time(NULL));
    }
    return rand();
}


char *rebrick_util_time_r(char * str){
    time_t current_time=time(NULL);
    ctime_r(&current_time,str);
    //remove \n
    str[strlen(str)-1]=0;
    return str;

}


int32_t rebrick_util_addr_to_roksit_addr(const struct sockaddr *addr, rebrick_sockaddr_t *sock){

    if(addr->sa_family==AF_INET){
        memcpy(&sock->v4,addr,sizeof(struct sockaddr_in));
    }
     if(addr->sa_family==AF_INET6){
        memcpy(&sock->v6,addr,sizeof(struct sockaddr_in6));
    }
    return REBRICK_SUCCESS;

}


int32_t rebrick_util_addr_to_ip_string(const rebrick_sockaddr_t *sock,char buffer[REBRICK_IP_STR_LEN]){
     if(sock->base.sa_family==AF_INET){

        uv_ip4_name(&sock->v4,buffer,16);

    }
    if(sock->base.sa_family==AF_INET6){

        uv_ip6_name(&sock->v6,buffer,45);

    }
    return REBRICK_SUCCESS;

}

int32_t rebrick_util_addr_to_port_string(const rebrick_sockaddr_t *sock,char buffer[REBRICK_PORT_STR_LEN]){

     if(sock->base.sa_family==AF_INET){

       sprintf(buffer,"%d",ntohs(sock->v4.sin_port));

    }
    if(sock->base.sa_family==AF_INET6){

        sprintf(buffer,"%d",ntohs(sock->v6.sin6_port));

    }
    return REBRICK_SUCCESS;

}


int32_t rebrick_util_to_socket(rebrick_sockaddr_t *sock, const char *ip,const char*port){

    if (uv_ip6_addr(ip, atoi(port), cast(&sock->v6, struct sockaddr_in6 *)) < 0)
    {

        if (uv_ip4_addr(ip, atoi(port), cast(&sock->v4, struct sockaddr_in *)) < 0)
        {

            return REBRICK_ERR_BAD_IP_PORT_ARGUMENT;
        }
    }
    return REBRICK_SUCCESS;

}

int32_t rebrick_util_ip_port_to_addr(const char *ip,const char*port,rebrick_sockaddr_t *sock){
    fill_zero(sock,sizeof(rebrick_sockaddr_t));
    if (uv_ip6_addr(ip, atoi(port), cast(&sock->v6, struct sockaddr_in6 *)) < 0)
    {

        if (uv_ip4_addr(ip, atoi(port), cast(&sock->v4, struct sockaddr_in *)) < 0)
        {

            return REBRICK_ERR_BAD_IP_PORT_ARGUMENT;
        }
    }
    return REBRICK_SUCCESS;

}



int32_t rebrick_util_file_read_allbytes(const char *file,char **buffer,size_t *len){
    FILE *fileptr;
    int64_t filelen;
    fileptr=fopen(file,"rb");
    if(!fileptr)
    return REBRICK_ERR_BAD_ARGUMENT;
    fseek(fileptr,0,SEEK_END);
    filelen=ftell(fileptr);
    rewind(fileptr);
    char *temp=malloc(filelen+1);
    if(!temp)
    {
        fclose(fileptr);
        exit(1);
    }
    fill_zero(temp,filelen+1);
    fread(temp,filelen,1,fileptr);
    fclose(fileptr);
    *buffer=temp;
    *len=filelen;
    return REBRICK_SUCCESS;

}


int32_t rebrick_util_ip_equal(const rebrick_sockaddr_t *src,const rebrick_sockaddr_t *dst){
    if(!src || !dst)
    return 0;
    if(src->base.sa_family==AF_INET)
    return memcmp(&src->v4.sin_addr,&dst->v4.sin_addr,sizeof(struct in_addr))==0?1:0;
    return memcmp(&src->v6.sin6_addr,&dst->v6.sin6_addr,sizeof(struct in6_addr))==0?1:0;

}


