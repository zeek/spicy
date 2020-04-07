// $Id$
//
// Simple auto-growing vectors. The value of elements not yet initialized is
// set to zero.

#ifndef JRX_VECTOR_H
#define JRX_VECTOR_H

#include <assert.h>

static const int VECTOR_DEFAULT_SIZE = 2;
static const double VECTOR_GROWTH_FACTOR = 1.5;

// #macro-start
#define DECLARE_VECTOR(name, vec_elem_t, vec_size_t)                                               \
                                                                                                   \
    typedef vec_elem_t vec_##name##_elem_t;                                                        \
    typedef vec_size_t vec_##name##_size_t;                                                        \
                                                                                                   \
    typedef struct vec_##name {                                                                    \
        vec_size_t size;   /* Largest index + 1 written to so far. */                              \
        vec_size_t max;    /* Number of slots allocated. */                                        \
        vec_elem_t* elems; /* Elements themselves. */                                              \
    } vec_##name;                                                                                  \
                                                                                                   \
    static inline int vec_##name##_resize(vec_##name* vec, vec_size_t nmax)                        \
    {                                                                                              \
        if ( nmax < VECTOR_DEFAULT_SIZE )                                                          \
            nmax = VECTOR_DEFAULT_SIZE;                                                            \
                                                                                                   \
        vec->elems = (vec_elem_t*)realloc(vec->elems, nmax * sizeof(vec_elem_t));                  \
        if ( ! vec->elems )                                                                        \
            return 0;                                                                              \
                                                                                                   \
        if ( nmax > vec->max )                                                                     \
            memset(&vec->elems[vec->max], 0, sizeof(vec_elem_t) * (nmax - vec->max));              \
                                                                                                   \
        vec->max = nmax;                                                                           \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline vec_##name* vec_##name##_create(vec_size_t size)                                 \
    {                                                                                              \
        vec_size_t max = size ? size : VECTOR_DEFAULT_SIZE;                                        \
                                                                                                   \
        vec_##name* vec = (vec_##name*)malloc(sizeof(vec_##name));                                 \
        if ( ! vec )                                                                               \
            return 0;                                                                              \
                                                                                                   \
        vec->elems = (vec_elem_t*)calloc(max, sizeof(vec_elem_t));                                 \
        if ( ! vec->elems ) {                                                                      \
            free(vec);                                                                             \
            return 0;                                                                              \
        }                                                                                          \
                                                                                                   \
        vec->max = max;                                                                            \
        vec->size = 0;                                                                             \
        return vec;                                                                                \
    }                                                                                              \
                                                                                                   \
    static inline void vec_##name##_delete(vec_##name* vec)                                        \
    {                                                                                              \
        free(vec->elems);                                                                          \
        free(vec);                                                                                 \
    }                                                                                              \
                                                                                                   \
    static inline vec_##name* vec_##name##_copy(vec_##name* vec)                                   \
    {                                                                                              \
        vec_##name* copy = vec_##name##_create(vec->max);                                          \
        if ( ! copy )                                                                              \
            return 0;                                                                              \
                                                                                                   \
        memcpy(copy->elems, vec->elems, vec->max * sizeof(vec_elem_t));                            \
        copy->max = vec->max;                                                                      \
        return copy;                                                                               \
    }                                                                                              \
                                                                                                   \
    static inline vec_elem_t* vec_##name##_freeze(vec_##name* vec)                                 \
    {                                                                                              \
        vec_elem_t* elems = vec->elems;                                                            \
        free(vec);                                                                                 \
        return elems;                                                                              \
    }                                                                                              \
                                                                                                   \
    static inline vec_size_t vec_##name##_size(vec_##name* vec)                                    \
    {                                                                                              \
        return vec->size;                                                                          \
    }                                                                                              \
                                                                                                   \
    static inline int vec_##name##_set(vec_##name* vec, vec_size_t idx, vec_elem_t elem)           \
    {                                                                                              \
        if ( idx >= vec->max ) {                                                                   \
            int nmax = vec->max;                                                                   \
            do {                                                                                   \
                nmax *= VECTOR_GROWTH_FACTOR;                                                      \
            } while ( idx >= nmax );                                                               \
                                                                                                   \
            if ( ! vec_##name##_resize(vec, nmax) )                                                \
                return 0;                                                                          \
        }                                                                                          \
                                                                                                   \
        assert(idx < vec->max);                                                                    \
                                                                                                   \
        vec->elems[idx] = elem;                                                                    \
        if ( idx >= vec->size )                                                                    \
            vec->size = idx + 1;                                                                   \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
                                                                                                   \
    static inline vec_size_t vec_##name##_append(vec_##name* vec, vec_elem_t elem)                 \
    {                                                                                              \
        assert(vec);                                                                               \
        vec_size_t idx = vec->size;                                                                \
        vec_##name##_set(vec, idx, elem);                                                          \
        return idx;                                                                                \
    }                                                                                              \
                                                                                                   \
    static inline vec_elem_t vec_##name##_get(vec_##name* vec, vec_size_t idx)                     \
    {                                                                                              \
        assert(vec);                                                                               \
        assert(vec->elems);                                                                        \
        if ( idx >= vec->max ) {                                                                   \
            vec_elem_t zero;                                                                       \
            memset(&zero, 0, sizeof(zero));                                                        \
            return zero;                                                                           \
        }                                                                                          \
                                                                                                   \
        return vec->elems[idx];                                                                    \
    }                                                                                              \
                                                                                                   \
// #macro-end

#define vec_for_each(name, vec, var)                                                               \
    vec_##name##_elem_t var;                                                                       \
    vec_##name##_size_t __j##var;                                                                  \
    if ( (vec)->size )                                                                             \
        var = (vec)->elems[0];                                                                     \
    else                                                                                           \
        bzero(&var, sizeof(var));                                                                  \
    for ( __j##var = 0; __j##var < (vec)->size;                                                    \
          __j##var++, var = (vec)->elems[__j##var < (vec)->size ? __j##var : 0] )


#endif
