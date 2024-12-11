#include <unistd.h>
#include <cstring>
#include <iostream>

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
    }*mallocMetadata;

    MallocMetadata metaChain;
    size_t freeBlocks;
    size_t freeBytes;
    size_t totBlocks;
    size_t totBytes;

    mallocMetadata get_metaData(void* p);
    void* get_allocPtr(mallocMetadata m);
    void* alloc_to_free_block(size_t size);
    void add_to_list(mallocMetadata block);
    void remove_from_list(mallocMetadata block);

    BlockManager();
public:
    static BlockManager& getInstance() // make SmallShell singleton
    {
        static BlockManager instance; // Guaranteed to be destroyed.
        // Instantiated on first use.
        return instance;
    }    
    void* alloc_block(size_t size);
    void alloc_free(void* p);

    static size_t get_metaData_size();
    size_t get_size(void* p);
    size_t get_totBlocks();
    size_t get_totBytes();
    size_t get_freeBlocks();
    size_t get_freeBytes();
};

BlockManager::BlockManager() : metaChain(), freeBlocks(0), freeBytes(0), totBlocks(0), totBytes(0){}

void BlockManager::add_to_list(mallocMetadata block){
    mallocMetadata next_meta = metaChain.next;
    mallocMetadata prev_meta = &metaChain;
    while(next_meta){
        if((void*)next_meta > (void*)block){
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

void* BlockManager::alloc_to_free_block(size_t size){
    mallocMetadata curr = &metaChain;
    while(curr){
        if(curr->is_free)
            if(curr->size >= size){
                curr->is_free = false;
                freeBlocks--;
                freeBytes-=curr->size;
                remove_from_list(curr);
                return get_allocPtr(curr);
            }
        curr=curr->next;
    }
    return (void*)-1;
}

void* BlockManager::alloc_block(size_t size){
    void* res = alloc_to_free_block(size);
    if(res != (void*)-1)
        return res;
    DO_SBRK(res, size+sizeof(struct MallocMetadata));
    mallocMetadata block = (mallocMetadata)res;
    totBlocks++;
    totBytes+=size;
    block->is_free = false;
    block->size = size;
    return get_allocPtr(block);
}

void BlockManager::alloc_free(void* p){
    if(!p)
        return;
    mallocMetadata m = get_metaData(p);
    if(m->is_free)
        return;
    m->is_free = true;
    freeBlocks++;
    freeBytes += m->size;
    add_to_list(m);
}

BlockManager::mallocMetadata BlockManager::get_metaData(void* p){
    return (BlockManager::mallocMetadata)((uintptr_t)p - sizeof(struct MallocMetadata));
}

size_t BlockManager::get_size(void* p){
    return get_metaData(p)->size;
}

void* BlockManager::get_allocPtr(mallocMetadata m){
    return (void*)((uintptr_t)m + sizeof(struct MallocMetadata));
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
    if(size > 1e8 || size == 0)
        return nullptr;
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
    if(size > 1e8 || size == 0)
        return nullptr;
    if(!oldp)
        return BlockManager::getInstance().alloc_block(size);
    void* res;
    if(BlockManager::getInstance().get_size(oldp) < size){
        res = BlockManager::getInstance().alloc_block(size);
        if(!res)
            return nullptr;
    }else
        return oldp;
    std::memmove(res,oldp,BlockManager::getInstance().get_size(oldp));
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
