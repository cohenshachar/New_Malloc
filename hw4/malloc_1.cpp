#include <unistd.h>

void* smalloc(size_t size){
    if(size > 1e8 || size == 0)
        return nullptr;
    void* res = sbrk(size);
    if(res == (void*)-1)
        return nullptr;
    return res;
}