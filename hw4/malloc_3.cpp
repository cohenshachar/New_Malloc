#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

#define MAX_ORDER 10
#define KB 1024

#define DO_SBRK(res, size) do{   \
    res = sbrk(size);            \
    if(res == (void*)-1)         \
        return nullptr;          \
}while(0)                        \

class BlockManager{
private:
    typedef struct MallocMetadata{
        size_t size;
        bool is_free; 
        MallocMetadata* next;
        MallocMetadata* prev;
        MallocMetadata() : size(0), is_free(false), next(nullptr), prev(nullptr){}
    }* mallocMetadata;

    uintptr_t offset;
    size_t freeBlocks;
    size_t freeBytes;
    size_t totBlocks;
    size_t totBytes;
    bool init_pool_flag; 
    MallocMetadata metaChain[MAX_ORDER+1];
    
    const int BLOCKS_SET_SIZE = 128;
    const int BLOCKS_SET_NUM = 32;

    mallocMetadata get_metaData(void* p);
    void* get_allocPtr(mallocMetadata m);

    mallocMetadata split(mallocMetadata m);
    mallocMetadata pop(int list_index);
    void add_to_list(int list_index, mallocMetadata block);
    void remove_from_list(mallocMetadata block);
    bool isEmpty(MallocMetadata& list);
    bool join(mallocMetadata* free_block);
    bool can_join(mallocMetadata free_block, size_t size, size_t dest_size);
    int get_order(size_t size);
    
    BlockManager();
public:
    static BlockManager& getInstance()
    {
        static BlockManager instance;
        return instance;
    }    
    void* alloc_block(size_t size);
    void* lalloc_block(size_t size);
    void* realloc_block(void* oldp, size_t size);
    void alloc_free(void* p);
    void* lazy_init();
    bool isLargeAlloc(size_t size);

    static size_t get_metaData_size();
    size_t get_size(void* p);
    size_t get_totBlocks();
    size_t get_totBytes();
    size_t get_freeBlocks();
    size_t get_freeBytes();
};

BlockManager::BlockManager() : offset(0),freeBlocks(0), freeBytes(0), totBlocks(0), totBytes(0),init_pool_flag(true),metaChain(){
}

void* BlockManager::lazy_init(){
    if(!init_pool_flag)
        return (void*)-1;
    void* ptr;
    DO_SBRK(ptr, BLOCKS_SET_NUM*BLOCKS_SET_SIZE*KB);
    offset = (uintptr_t)ptr;
    for(int i = 0; i < BLOCKS_SET_NUM; i++){
        uintptr_t block_addr = (uintptr_t)ptr + i*(BLOCKS_SET_SIZE*KB);
        mallocMetadata block = (mallocMetadata)block_addr;
        block->size = BLOCKS_SET_SIZE*KB - sizeof(struct MallocMetadata);
        block->is_free = true;
        block->next = nullptr;
        block->prev = nullptr;
        add_to_list(MAX_ORDER, block);
    }
    freeBlocks = BLOCKS_SET_NUM;
    freeBytes = BLOCKS_SET_NUM*(BLOCKS_SET_SIZE*KB - sizeof(struct MallocMetadata));
    totBlocks = freeBlocks;
    totBytes = freeBytes;
    init_pool_flag = false;
    return (void*)-1;
}

bool BlockManager::isEmpty(MallocMetadata& list){
    return list.next == nullptr;
}

void BlockManager::add_to_list(int list_index, mallocMetadata block){
    mallocMetadata next_meta = metaChain[list_index].next;
    mallocMetadata prev_meta = &metaChain[list_index];
    while(next_meta){
        if((uintptr_t)next_meta > (uintptr_t)block){
            block->next = next_meta;
            block->prev = prev_meta;
            next_meta->prev = block;
            prev_meta->next = block;
            return;
        }
        prev_meta = next_meta;
        next_meta = next_meta->next;
    }
    block->next = nullptr;
    block->prev = prev_meta;
    prev_meta->next = block;
}

void BlockManager::remove_from_list(mallocMetadata block){
    block->prev->next = block->next;
    if(block->next)
        block->next->prev = block->prev;
    block->prev = nullptr;
    block->next = nullptr;
}

BlockManager::mallocMetadata BlockManager::pop(int list_index){
    if(!isEmpty(metaChain[list_index])){
        mallocMetadata res = metaChain[list_index].next;
        remove_from_list(res);
        return res;
    }
    return nullptr;
}

BlockManager::mallocMetadata BlockManager::split(mallocMetadata m){
    size_t half_of_block = (m->size + sizeof(struct MallocMetadata))/2;
    mallocMetadata res = (mallocMetadata)((uintptr_t)m + half_of_block);
    freeBlocks++;
    totBlocks++;
    freeBytes -= sizeof(struct MallocMetadata);
    totBytes -= sizeof(struct MallocMetadata);
    m->size = half_of_block - sizeof(struct MallocMetadata);
    res->size = m->size;
    res->is_free = true;
    res->next = nullptr;
    res->prev = nullptr;
    return res;
}

bool BlockManager::can_join(mallocMetadata free_block, size_t size, size_t dest_size){
    if(get_order(dest_size) == -1)
        return false;
    if(size  >= dest_size)
        return true;
    mallocMetadata buddy = (mallocMetadata)((((uintptr_t)free_block - offset)^size)+offset);
    if(!(buddy->is_free) || (buddy->size != free_block->size))
        return false;
    if((uintptr_t)buddy < (uintptr_t)free_block)
        return can_join(buddy, size*2, dest_size);
    return can_join(free_block, size*2, dest_size);
}

bool BlockManager::join(mallocMetadata* free_block){
    if(get_order((*free_block)->size) == MAX_ORDER)
        return false;
    mallocMetadata buddy = (mallocMetadata)((((uintptr_t)(*free_block) - offset)^((*free_block)->size + sizeof(struct MallocMetadata)))+offset);
    if(!(buddy->is_free) || (buddy->size != (*free_block)->size))
        return false;
    remove_from_list(buddy);
    if((uintptr_t)buddy < (uintptr_t)(*free_block))
        *free_block = buddy;
    (*free_block)->size = (*free_block)->size * 2 + sizeof(struct MallocMetadata);
    (*free_block)->is_free = true;
    (*free_block)->next = nullptr;
    (*free_block)->prev = nullptr;
    freeBlocks--;
    totBlocks--;
    freeBytes += sizeof(struct MallocMetadata);
    totBytes += sizeof(struct MallocMetadata);
    return true;
}


void* BlockManager::alloc_block(size_t size){
    int dest_ord = get_order(size);
    if(dest_ord == -1)
        return nullptr;
    for(int src_ord = dest_ord; src_ord <= MAX_ORDER; src_ord++){
        if(isEmpty(metaChain[src_ord]))
            continue;
        while(src_ord >= dest_ord){
            mallocMetadata buff = pop(src_ord);
            if(src_ord == dest_ord){
                buff->is_free = false;
                freeBlocks--;
                freeBytes -= buff->size;
                return get_allocPtr(buff);
            }else{
                src_ord--;
                add_to_list(src_ord,split(buff));
                add_to_list(src_ord,buff);
            }
        }
        break;
    }
    return nullptr;
}

void* BlockManager::realloc_block(void* oldp, size_t size){
    mallocMetadata oldm = get_metaData(oldp);
    if(oldm->size >= size)
        return oldp;
    if(can_join(oldm,oldm->size+sizeof(struct MallocMetadata), size)){
        freeBytes += oldm->size;
        oldm->is_free = true;
        while(oldm->size < size)
            join(&oldm);
        freeBytes -= oldm->size;
        oldm->is_free = false;
        return get_allocPtr(oldm);
    }
    return alloc_block(size);
}

void* BlockManager::lalloc_block(size_t size){
    mallocMetadata block = (mallocMetadata)mmap(nullptr, size+sizeof(struct MallocMetadata), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    block->is_free = false;
    block->next = nullptr;
    block->prev = nullptr;
    block->size = size;
    totBlocks++;
    totBytes += size;
    return get_allocPtr(block);
}

void BlockManager::alloc_free(void* p){
    if(!p)
        return;
    mallocMetadata m = get_metaData(p);
    if(m->is_free)
        return;
    if(isLargeAlloc(m->size)){
        totBlocks--;
        totBytes -= m->size;
        int size_allocated = m->size+sizeof(struct MallocMetadata);
        int pageSize = sysconf(_SC_PAGESIZE);
        if(size_allocated%pageSize != 0)
            size_allocated += pageSize - size_allocated%pageSize;
        munmap((void*)m, size_allocated);
        return;
    }
    m->is_free = true;
    freeBlocks++;
    freeBytes += m->size;
    while(join(&m)){}
    add_to_list(get_order(m->size), m);
}

int BlockManager::get_order(size_t size){
    int res = 0;
    for(size_t bytes = BLOCKS_SET_SIZE ; res <= MAX_ORDER; bytes *= 2, res++){
        if(size <= bytes - sizeof(struct MallocMetadata))
            return res;
    }
    return -1;
}

BlockManager::mallocMetadata BlockManager::get_metaData(void* p){
    return (mallocMetadata)((uintptr_t)p - sizeof(struct MallocMetadata));
}

size_t BlockManager::get_size(void* p){
    return get_metaData(p)->size;
}

void* BlockManager::get_allocPtr(mallocMetadata m){
    return (void*)((uintptr_t)m + sizeof(struct MallocMetadata));
}

bool BlockManager::isLargeAlloc(size_t size){
    return size > BLOCKS_SET_SIZE*KB - sizeof(struct MallocMetadata);
}

size_t BlockManager::get_metaData_size(){
    return sizeof(struct MallocMetadata);
}
size_t BlockManager::get_totBlocks(){
    return totBlocks;
}
size_t BlockManager::get_totBytes(){
    return totBytes;
}
size_t BlockManager::get_freeBlocks(){
    return freeBlocks;
}
size_t BlockManager::get_freeBytes(){
    return freeBytes;
}

void* smalloc(size_t size){
    if(!BlockManager::getInstance().lazy_init() || size > 1e8 || size == 0)
        return nullptr;
    if(BlockManager::getInstance().isLargeAlloc(size))
        return BlockManager::getInstance().lalloc_block(size);
    return BlockManager::getInstance().alloc_block(size);
}

void* scalloc(size_t num, size_t size){
    void* res = smalloc(num*size);
    if(!res)
        return nullptr;
    std::memset(res,0,num*size);
    return res;
}

void sfree(void* p){
    BlockManager::getInstance().alloc_free(p);
}

void* srealloc(void* oldp, size_t size){
    if(!BlockManager::getInstance().lazy_init() || size > 1e8 || size == 0)
        return nullptr;
    if(!oldp)
        return smalloc(size);
    void* res;
    if(BlockManager::getInstance().isLargeAlloc(size)){
        if(size == BlockManager::getInstance().get_size(oldp))
            return oldp;
        res = BlockManager::getInstance().lalloc_block(size);
    }else
        res = BlockManager::getInstance().realloc_block(oldp,size);
    if(!res)
        return nullptr;
    if(res == oldp)
        return oldp;
    size_t to_copy = BlockManager::getInstance().get_size(oldp) > size ? size : BlockManager::getInstance().get_size(oldp);
    std::memmove(res,oldp,to_copy);
    sfree(oldp);
    return res;
}

size_t _num_free_blocks(){
    return BlockManager::getInstance().get_freeBlocks();
}
size_t _num_free_bytes(){
    return BlockManager::getInstance().get_freeBytes();
}
size_t _num_allocated_blocks(){
    return BlockManager::getInstance().get_totBlocks();
}
size_t _num_allocated_bytes(){
    return BlockManager::getInstance().get_totBytes();
}
size_t _num_meta_data_bytes(){
    return BlockManager::get_metaData_size()*(BlockManager::getInstance().get_totBlocks());
}
size_t _size_meta_data(){
    return BlockManager::get_metaData_size();
}
