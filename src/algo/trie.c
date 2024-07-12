#include "trie.h"

trie_node* init_node()
{
    trie_node* root = (trie_node*) malloc(sizeof(trie_node));
    for(int i =0 ; i< 26 ; i++)
    {
        root->child_node[i] = NULL;
    }

    root->word_end = false;  
}

trie_node* insert_key(trie_node* root, char* key, int len)
{
    trie_node* curr_node;
    curr_node = root;

    for( int i =0; i< len ; ++i)
    {
        if(curr_node->child_node[key[i] - 'a'] == NULL)
            curr_node->child_node[key - 'a'] = init_node();
        
        curr_node = curr_node->child_node[key - 'a']; 
    }
    
    curr_node->word_end = true;

    return curr_node;    

}

bool search_key(trie_node* root, char* key, int len)
{
    trie_node* curr_node;

    curr_node = root;

    for(int i =0; i< len ; ++i)
    {
        if(curr_node->child_node[key[i] - 'a'] == NULL)
            return false;
    }

    return true;

}