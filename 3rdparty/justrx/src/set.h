// $Id$
//
// Simple sets of fixed-sized value types (which must be value-copyable).
//
// TODO: We should use a heap structure rather than a bubbling at insertion.

#ifndef JRX_SET_H
#define JRX_SET_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static const int SET_DEFAULT_SIZE = 2;
static const double SET_GROWTH_FACTOR = 1.5;

#define SET_STD_EQUAL(a, b) (a < b ? -1 : (a == b ? 0 : 1))

// #macro-start
#define DECLARE_SET(name, set_elem_t, set_size_t, cmp_func)                                        \
                                                                                                   \
    struct set_##name {                                                                            \
        set_size_t size;   /* Current number of elements */                                        \
        set_size_t max;    /* Maximum number of elements we have space for. */                     \
        set_elem_t* elems; /* Elements themselves. */                                              \
    };                                                                                             \
                                                                                                   \
    struct frozen_set_##name {                                                                     \
        set_size_t size;    /* Number of elements */                                               \
        set_elem_t elems[]; /* Elements themselves. */                                             \
    };                                                                                             \
                                                                                                   \
    typedef struct set_##name set_##name;                                                          \
    typedef struct frozen_set_##name frozen_set_##name;                                            \
                                                                                                   \
    typedef set_elem_t set_##name##_elem_t;                                                        \
    typedef set_size_t set_##name##_size_t;                                                        \
                                                                                                   \
    static inline set_size_t min_##name(set_size_t a, set_size_t b)                                \
    {                                                                                              \
        return a < b ? a : b;                                                                      \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_resize(set_##name* set, set_size_t nsize)                       \
    {                                                                                              \
        if ( nsize < SET_DEFAULT_SIZE )                                                            \
            nsize = SET_DEFAULT_SIZE;                                                              \
        set->elems = realloc(set->elems, nsize * sizeof(set_elem_t));                              \
        if ( ! set->elems )                                                                        \
            return 0;                                                                              \
                                                                                                   \
        set->max = nsize;                                                                          \
                                                                                                   \
        if ( set->size > nsize )                                                                   \
            set->size = nsize;                                                                     \
                                                                                                   \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline set_##name* set_##name##_create(set_size_t size)                                 \
    {                                                                                              \
        set_size_t max = size ? size : SET_DEFAULT_SIZE;                                           \
                                                                                                   \
        set_##name* set = (set_##name*)malloc(sizeof(set_##name));                                 \
        if ( ! set )                                                                               \
            return 0;                                                                              \
                                                                                                   \
        set->elems = (set_elem_t*)malloc(max * sizeof(set_elem_t));                                \
        if ( ! set->elems ) {                                                                      \
            free(set);                                                                             \
            return 0;                                                                              \
        }                                                                                          \
                                                                                                   \
        set->size = 0;                                                                             \
        set->max = max;                                                                            \
        return set;                                                                                \
    }                                                                                              \
                                                                                                   \
    static inline void set_##name##_delete(set_##name* set)                                        \
    {                                                                                              \
        if ( set ) {                                                                               \
            if ( set->elems )                                                                      \
                free(set->elems);                                                                  \
            free(set);                                                                             \
        }                                                                                          \
    }                                                                                              \
                                                                                                   \
    static inline set_##name* set_##name##_copy(set_##name* set)                                   \
    {                                                                                              \
        set_##name* copy = set_##name##_create(set->max);                                          \
        if ( ! copy )                                                                              \
            return 0;                                                                              \
                                                                                                   \
        assert(set->elems);                                                                        \
        memcpy(copy->elems, set->elems, set->size * sizeof(set_elem_t));                           \
        copy->size = set->size;                                                                    \
        return copy;                                                                               \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_empty(set_##name* set)                                          \
    {                                                                                              \
        return set->size == 0;                                                                     \
    }                                                                                              \
                                                                                                   \
    /* Public interface: Returns non-zero if found. */                                             \
    /* Private interface: Returns index+1 if found. */                                             \
    static inline set_size_t set_##name##_contains(set_##name* set, set_elem_t elem)               \
    {                                                                                              \
        assert(set);                                                                               \
        if ( ! set->size )                                                                         \
            return 0;                                                                              \
                                                                                                   \
        set_size_t min = 0;                                                                        \
        set_size_t max = set->size - 1;                                                            \
                                                                                                   \
        while ( min <= max ) {                                                                     \
            set_size_t m = (min + max) / 2;                                                        \
                                                                                                   \
            int cmp = cmp_func(set->elems[m], elem);                                               \
                                                                                                   \
            if ( cmp == 0 )                                                                        \
                return m + 1;                                                                      \
                                                                                                   \
            if ( cmp < 0 )                                                                         \
                min = m + 1;                                                                       \
            else if ( ! m )                                                                        \
                break;                                                                             \
            else                                                                                   \
                max = m - 1;                                                                       \
        }                                                                                          \
                                                                                                   \
        return 0;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline set_size_t set_##name##_size(set_##name* set)                                    \
    {                                                                                              \
        assert(set);                                                                               \
        return set->size;                                                                          \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_insert(set_##name* set, set_elem_t elem)                        \
    {                                                                                              \
        if ( set_##name##_contains(set, elem) )                                                    \
            return 1;                                                                              \
                                                                                                   \
        if ( set->size + 1 > set->max ) {                                                          \
            if ( ! set_##name##_resize(set, (set_size_t)(set->size * SET_GROWTH_FACTOR)) )         \
                return 0;                                                                          \
        }                                                                                          \
                                                                                                   \
        assert(set);                                                                               \
        assert(set->elems);                                                                        \
        set->elems[set->size] = elem;                                                              \
        set->size++;                                                                               \
                                                                                                   \
        /* Bubble it to the right place */                                                         \
        set_size_t i;                                                                              \
        for ( i = set->size - 1; i > 0; i-- ) {                                                    \
            if ( cmp_func(set->elems[i], set->elems[i - 1]) >= 0 )                                 \
                break;                                                                             \
                                                                                                   \
            set_elem_t tmp = set->elems[i];                                                        \
            set->elems[i] = set->elems[i - 1];                                                     \
            set->elems[i - 1] = tmp;                                                               \
        }                                                                                          \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_remove(set_##name* set, set_elem_t elem)                        \
    {                                                                                              \
        set_size_t idx = set_##name##_contains(set, elem);                                         \
        if ( ! idx )                                                                               \
            return 1;                                                                              \
                                                                                                   \
        if ( idx < set->size )                                                                     \
            memcpy(set->elems + idx - 1, set->elems + idx,                                         \
                   (set->size - idx) * sizeof(set_elem_t));                                        \
                                                                                                   \
        set->size--;                                                                               \
                                                                                                   \
        set_size_t gsize = (set_size_t)(set->size / SET_GROWTH_FACTOR);                            \
                                                                                                   \
        return gsize && set->size >= gsize ? 1 : set_##name##_resize(set, gsize);                  \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_equal(set_##name* s1, set_##name* s2)                           \
    {                                                                                              \
        if ( s1->size != s2->size )                                                                \
            return 0;                                                                              \
                                                                                                   \
        set_size_t i;                                                                              \
        for ( i = 0; i < s1->size; i++ ) {                                                         \
            if ( cmp_func(s1->elems[i], s2->elems[i]) != 0 )                                       \
                return 0;                                                                          \
        }                                                                                          \
                                                                                                   \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_join(set_##name* set, const set_##name* other)                  \
    {                                                                                              \
        set_size_t i;                                                                              \
        for ( i = 0; i < other->size; i++ ) {                                                      \
            if ( ! set_##name##_insert(set, other->elems[i]) )                                     \
                return 0;                                                                          \
        }                                                                                          \
                                                                                                   \
        return 1;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline set_size_t set_##name##_begin(set_##name* set)                                   \
    {                                                                                              \
        return 0;                                                                                  \
    }                                                                                              \
                                                                                                   \
    static inline set_size_t set_##name##_end(set_##name* set)                                     \
    {                                                                                              \
        return set->size;                                                                          \
    }                                                                                              \
                                                                                                   \
    static inline frozen_set_##name* set_##name##_freeze(set_##name* set)                          \
    {                                                                                              \
        size_t size = sizeof(frozen_set_##name) + set->size * sizeof(set_elem_t);                  \
        frozen_set_##name* fset = (frozen_set_##name*)malloc(size);                                \
        if ( ! set )                                                                               \
            return 0;                                                                              \
                                                                                                   \
        fset->size = set->size;                                                                    \
        memcpy(fset->elems, set, set->size * sizeof(set_elem_t));                                  \
        set_##name##_delete(set);                                                                  \
        return fset;                                                                               \
    }                                                                                              \
                                                                                                   \
    static inline void frozen_set_##name##_delete(frozen_set_##name* set)                          \
    {                                                                                              \
        free(set);                                                                                 \
    }                                                                                              \
                                                                                                   \
    static inline set_size_t frozen_set_##name##_size(frozen_set_##name* set)                      \
    {                                                                                              \
        return set->size;                                                                          \
    }                                                                                              \
                                                                                                   \
    static inline set_elem_t frozen_set_##name##_index(frozen_set_##name* set, set_size_t idx)     \
    {                                                                                              \
        return set->elems[idx];                                                                    \
    }                                                                                              \
                                                                                                   \
    static inline int set_##name##_iter_equal(set_size_t iter1, set_size_t iter2)                  \
    {                                                                                              \
        return iter1 == iter2;                                                                     \
    }                                                                                              \
                                                                                                   \
    static inline set_size_t set_##name##_iter_next(set_size_t iter)                               \
    {                                                                                              \
        return iter + 1;                                                                           \
    }                                                                                              \
                                                                                                   \
    static inline set_elem_t set_##name##_iter_deref(set_##name* set, set_size_t iter)             \
    {                                                                                              \
        return set->elems[iter];                                                                   \
    }                                                                                              \
                                                                                                   \
// #macro-end

#define set_for_each(name, set, var)                                                               \
    assert((set)->elems);                                                                          \
    set_##name##_elem_t var;                                                                       \
    set_##name##_size_t __i##var;                                                                  \
    if ( (set)->size )                                                                             \
        var = (set)->elems[0];                                                                     \
    for ( __i##var = 0; __i##var < (set)->size;                                                    \
          __i##var++, var = (set)->elems[__i##var < (set)->size ? __i##var : 0] )
#endif
