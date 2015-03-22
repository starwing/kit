/* kit - a simple type system
 * Xavier Wang (c) 2015, MIT license
 *
 * kit is a simple library for a type system, inspired by llib[1]. 
 * it can be used to simplifiy developing. kit offers:
 *      - ref-counted object/array
 *      - pointer-compare symbol
 *      - array of refs (refarray) support
 *      - a object pool implement
 *      - a hashtable implement
 *
 * routines ends with '_' are unchecked version. all objects newed by
 * kit are recorded, and function such as kit_retain() will check
 * whether a void* pointer is from kit. using kit_retain_() means you
 * sure the pointer is really from kit.
 *
 * [1]: https://github.com/stevedonovan/llib
 */
#ifndef kit_h
#define kit_h


#include <stddef.h>

#ifdef __cplusplus
# define KIT_NS_BEGIN extern "C" {
# define KIT_NS_END   }
#else
# define KIT_NS_BEGIN
# define KIT_NS_END
#endif

#if !defined(KIT_API) && defined(_WIN32)
# ifdef KIT_IMPLEMENTATION
#  define KIT_API __declspec(dllexport)
# else
#  define KIT_API __declspec(dllimport)
# endif
#endif

#ifndef KIT_API
# define KIT_API extern
#endif

#ifndef kit_assert
# ifdef KIT_DEBUG
#  include <assert.h>
#  define kit_assert(exp) assert(exp)
# else
#  define kit_assert(exp) ((void)0)
# endif
#endif

#ifndef kit_check
# ifdef KIT_DEBUG
#  define kit_check(exp, value) (kit_assert(exp), (value))
# else
#  define kit_check(exp, value) (value)
# endif
#endif

#define kit_checkobject(P) kit_check(kit_isarray(P), P)
#define kit_checktype(P,T) kit_check(kit_typeid(P)==(T)->type_id, P)


KIT_NS_BEGIN


typedef struct kit_State  kit_State;
typedef struct kit_Type   kit_Type;
typedef struct kit_Symbol kit_Symbol;
typedef struct kit_Seq    kit_Seq;
typedef struct kit_Entry  kit_Entry;
typedef        kit_Entry *kit_Table;
typedef            void* *kit_Pool;

typedef void *kit_Alloc (kit_State *S, void *p, size_t newsize, size_t oldsize);
typedef void  kit_Panic (kit_State *S, const char *msg, void *ud);


/* kit global sevices */

KIT_API kit_State *kit_state    (void);
KIT_API kit_State *kit_setstate (kit_State *S);
KIT_API kit_State *kit_newstate (kit_Alloc *allocf);
KIT_API void       kit_close    (kit_State *S);

KIT_API void       kit_setpanicf (kit_State *S, kit_Panic *panicf, void *ud);
KIT_API kit_Panic *kit_getpanicf (kit_State *S, void **pud);
KIT_API void       kit_panic     (kit_State *S, const char *msg);

KIT_API size_t kit_sweep    (kit_State *S);
KIT_API size_t kit_totalmem (kit_State *S); /* only useful when debug */


/* kit types routines */

struct kit_Type {
    kit_Symbol  *name;      /* ro */
    kit_Alloc   *alloc;
    void (*init_object) (kit_Type *t, void *ptr);
    void (*drop_object) (kit_Type *t, void *ptr);
    void (*close_type)  (kit_Type *t);

    unsigned type_id;      /* ro */
    unsigned header_size;  /* ro */
    unsigned obj_size;     /* ro */
    unsigned instances;    /* ro, only useful when debug */
};

#define KIT_BUILTIN_TYPES(X) \
 /* X(name,   "symbol",     obj_size,      header_type      ) */\
    X(TYPE,   "kit_Type",   1,             kit_ObjectHeader )   \
    X(SYMBOL, "kit_Symbol", 1,             kit_SymbolHeader )   \
    X(REF,    "kit_Ref",    sizeof(void*), kit_ObjectHeader )   \

typedef enum kit_BuiltinTypeId {
#define X(T,sym,os,h) KIT_TIDX_##T,
    KIT_BUILTIN_TYPES(X)
#undef  X
    KIT_TIDX_COUNT
} kit_BuiltinTypeId;

/* TS = type symbol, TP = type pointer */
#define KIT_TS(name) (kit_symbols(KIT_TIDX_##name))
#define KIT_TP(name) (kit_typebyid(KIT_TIDX_##name))

#define kit_type(T)       (kit_type_(KIT_(T)))
#define kit_ctype(T)      (kit_ctype_(KIT_(T), sizeof(T)))
#define kit_newtype(T,sz) (kit_newtype_(KIT_S(T), (sz)))

KIT_API kit_Type *kit_newtype_ (kit_Symbol *name, size_t type_size);
KIT_API kit_Type *kit_ctype_   (kit_Symbol *name, size_t obj_size);
KIT_API kit_Type *kit_type_    (kit_Symbol *name);
KIT_API kit_Type *kit_typebyid (unsigned type_id);


/* kit object routines */

typedef struct kit_ObjectHeader { /* all fields ro */
    unsigned type_id : 16;
      signed ref     : 16;
    unsigned len     : 32;
} kit_ObjectHeader;

#define kit_objectheader(P) ((kit_ObjectHeader*)kit_checkobject(P)-1)
#define kit_typeid(P)       (!(P) ? ~(unsigned)0 : kit_objectheader(P)->type_id)
#define kit_objecttype(P)   (!(P) ? NULL : kit_typebyid(kit_typeid(P)))
#define kit_len(P)          (!(P) ? 0 : kit_objectheader(P)->len)
#define kit_refcount(P)     (!(P) ? 0 : kit_objectheader(P)->ref)

#define kit_newobjects(T,sz)  ((T*)kit_newarray_(kit_ctype(T), (sz)))
#define kit_newobject(T)      kit_newobjects(T, 1)
#define kit_newrefs(T,sz)     ((T**)kit_newrefarray((sz)))
#define kit_delete(P)         (kit_delarray_(kit_checkobject(P)))

#define kit_spliceobjects(T,A,I,J) \
    ((T*)kit_splicearray_(kit_checkobject(A),(I),(J)))
#define kit_resizeobjects(T,A,sz) \
    ((T*)kit_resizearray_(kit_checkobject(A),(sz)))
#define kit_setobject(V,P) \
    (kit_safe_retain(P), kit_safe_release(V), (V)=(P))

#define kit_static(P)       (kit_static_(kit_checkobject(P)))
#define kit_retain(P)       (kit_retain_(kit_checkobject(P)))
#define kit_release(P)      (kit_release_(kit_checkobject(P)))
#define kit_safe_retain(P)  ((void)((P) && kit_retain(P)))
#define kit_safe_release(P) ((void)((P) && kit_release(P)))

#define kit_isrefs(P)      (kit_typeid(P)==KIT_TP(REF)->type_id)
#define kit_setrefs(A,I,P) kit_setobject((A)[I],P)
#define kit_retain_all(P)  (kit_retain_all_(kit_checkobject(P)))
#define kit_release_all(P) (kit_release_all_(kit_checkobject(P)))

KIT_API void *kit_newarray_    (kit_Type *t, size_t sz);
KIT_API void *kit_splicearray_ (void *ptr, int i, int j); 
KIT_API void *kit_resizearray_ (void *ptr, size_t sz);
KIT_API void  kit_delarray_    (void *ptr);
KIT_API int   kit_isarray      (void *ptr);

KIT_API int kit_static_  (void *ptr);
KIT_API int kit_retain_  (void *ptr);
KIT_API int kit_release_ (void *ptr);

KIT_API void *kit_newrefarray  (size_t sz);
KIT_API void  kit_retain_all_  (void *ptr);
KIT_API void  kit_release_all_ (void *ptr);


/* kit symbol routines */

typedef struct kit_SymbolHeader { /* all fields ro */
    struct kit_SymbolHeader *next;
    unsigned hash;
    kit_ObjectHeader h;
} kit_SymbolHeader;

#define KIT_(S)  (kit_symbol("" #S))
#define KIT_S(S) (kit_symbol(S))

#define kit_checksymbol(S)  kit_checktype(S, KIT_TP(SYMBOL))
#define kit_symbolheader(S) ((kit_SymbolHeader*)kit_checksymbol(S)-1)
#define kit_symbolhash(S)   (kit_symbolheader(S)->hash)

KIT_API kit_Symbol *kit_symbol  (const char *str);
KIT_API kit_Symbol *kit_lsymbol (const char *str, size_t len);
KIT_API kit_Symbol *kit_symbols  (size_t tidx);

KIT_API unsigned kit_calchash (const char *s, size_t len);


/* kit object pool */

typedef struct kit_PoolHeader { /* all fields ro */
    size_t used;
    size_t n;
} kit_PoolHeader;

#define kit_poolheader(P) ((kit_PoolHeader*)*(P)-1)
#define kit_poolsize(P)   (!*(P) ? 0 : kit_poolheader(P)->n)
#define kit_poolused(P)   (!*(P) ? 0 : kit_poolheader(P)->used)

#define kit_markobject(P,ptr)   (kit_mark_((P), kit_checkobject(ptr)))
#define kit_unmarkobject(P,ptr) (kit_unmark_((P), kit_checkobject(ptr)))

KIT_API void   kit_initpool    (kit_Pool *p, size_t size);
KIT_API void   kit_resizepool  (kit_Pool *p, size_t size);
KIT_API size_t kit_sweeppool   (kit_Pool *p);
KIT_API size_t kit_clearpool   (kit_Pool *p);
KIT_API void   kit_freepool    (kit_Pool *p);
KIT_API int    kit_nextpointer (kit_Pool *p, void ***ppptr);

KIT_API size_t kit_mark_    (kit_Pool *p, void *ptr);
KIT_API size_t kit_unmark_  (kit_Pool *p, void *ptr);
KIT_API int    kit_ismarked (kit_Pool *p, void *ptr);


/* kit table routines */

typedef struct kit_TableHeader { /* all fields ro */
    kit_Entry *lastfree;
    size_t n;
} kit_TableHeader;

struct kit_Entry {
    kit_Entry *next; /* ro */
    void *key;       /* ro */
    void *value;     /* rw */
};

#define kit_tableheader(T)      ((kit_TableHeader*)*(T)-1)
#define kit_tablesize(T)        (!*(T) ? 0 : kit_tableheader(T)->n)
#define kit_getfield(T,K)       (kit_gettable((T), KIT_S(K)))
#define kit_setfield(T,K,V)     kit_setreftable(T, KIT_S(K), V)
#define kit_setreftable(T,K,V)  kit_setobject(kit_settable((T),(K))->value, V)

KIT_API void   kit_inittable   (kit_Table *t, size_t init_size);
KIT_API void   kit_resettable  (kit_Table *t);
KIT_API void   kit_resizetable (kit_Table *t, size_t sz);
KIT_API void   kit_freetable   (kit_Table *t);
KIT_API size_t kit_counttable  (kit_Table *t);

KIT_API kit_Entry *kit_gettable (kit_Table *t, void *key);
KIT_API kit_Entry *kit_settable (kit_Table *t, void *key);

KIT_API int  kit_nextentry (kit_Table *t, kit_Entry **pcur);
KIT_API void kit_delentry  (kit_Entry *e);


KIT_NS_END

#endif /* end of include guard: kit_h */


/* implementations */

#ifdef KIT_IMPLEMENTATION


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


KIT_NS_BEGIN

/* limits */

#define KIT_MAX_SIZET             ((size_t)(~(size_t)0)-2)

#define KIT_MAX_REFCOUNT          (32700)
#define KIT_STAIC_OBJECT          (KIT_MAX_REFCOUNT+1)

/* at most ~(2^KIT_HASHLIMIT) bytes from a string
 * to compute its hash */
#if !defined(KIT_HASHLIMIT)
# define KIT_HASHLIMIT            5
#endif

/* minimum size for the string table (is the power of 2) */
#if !defined(KIT_MIN_SYMTABLE_SIZE)
# define KIT_MIN_SYMTABLE_SIZE   (1<<5)
#endif

/* minimum size for the object pool (is the power of 2) */
#if !defined(KIT_MIN_OBJPOOL_SIZE)
# define KIT_MIN_OBJPOOL_SIZE    (1<<5)
#endif

/* minimum size for the type table (must be the power of 2) */
#if !defined(KIT_MIN_TYPETAB_SIZE)
# define KIT_MIN_TYPETAB_SIZE    (1<<5)
#endif

/* minimum size for the sequence */
#if !defined(KIT_MIN_TABLE_SIZE)
# define KIT_MIN_TABLE_SIZE        4
#endif


/* unchecked macros */

#define kit_objectheader_(P) ((kit_ObjectHeader*)(P)-1)
#define kit_objecttype_(P)   (kit_typebyid(kit_objectheader_(P)->type_id))
#define kit_typeid_(P)       (kit_objectheader_(P)->type_id)
#define kit_len_(P)          (kit_objectheader_(P)->len)
#define kit_safelen_(P)      ((P) == NULL ? 0 : kit_objectheader_(P)->len)
#define kit_refcount_(P)     (kit_objectheader_(P)->ref)

#define kit_symbolheader_(S) ((kit_SymbolHeader*)(S)-1)
#define kit_symbolhash_(S)   (kit_symbolheader_(S)->hash)

/* statements enabled when debug */

#ifdef KIT_DEBUG
# define KIT_DEBUG_STMT(X) X
#else
# define KIT_DEBUG_STMT(X) /* nothing */
#endif


/* the global current kit state */
KIT_API kit_State *kit_current_state;
KIT_API kit_State *kit_default_state;

typedef struct kit_SymbolPool {
    kit_SymbolHeader **hash;
    size_t n;
} kit_SymbolPool;

struct kit_State {
    kit_Alloc *alloc;
    kit_Panic *panic;
    void *panic_ud;
    size_t totalmem; /* only useful when debug */

    unsigned seed; /* seed for symbols */
    kit_SymbolPool symbols;

    kit_Type builtin_types[KIT_TIDX_COUNT];
    kit_Type **types;
    size_t type_count;
    kit_Table typemap;

    kit_Pool free_objects;
    kit_Pool objects;
};

static size_t   kitH_calcsize (size_t size);
static unsigned kitH_calcmask (size_t size);


/* kit global memory routines */

static void kitG_outofmemory(kit_State *S)
{ kit_panic(S, "out of memory"); }

static void *kitG_alloc(kit_State *S, void *ptr, size_t newsize, size_t oldsize) {
    (void)S; (void)oldsize; /* not used */
    if (newsize == 0) {
        KIT_DEBUG_STMT(S->totalmem -= oldsize);
        free(ptr);
        return NULL;
    }
    KIT_DEBUG_STMT(S->totalmem += newsize);
    KIT_DEBUG_STMT(if (ptr) S->totalmem -= oldsize);
    return realloc(ptr, newsize);
}

static void **kitG_newarray(kit_State *S, size_t sz) {
    kit_ObjectHeader *h = (kit_ObjectHeader*)S->alloc(S, NULL,
            sizeof(kit_ObjectHeader) + sz*sizeof(void*), KIT_TIDX_REF);
    if (h == NULL) kitG_outofmemory(S);
    h->type_id = KIT_TIDX_REF;
    h->ref = KIT_STAIC_OBJECT;
    h->len = sz;
    memset(h+1, 0, sz*sizeof(void*));
    return (void**)(h+1);
}

static void **kitG_resizearray(kit_State *S, void **ptr, size_t newsize) {
    void **newptr;
    kit_ObjectHeader *h = kit_objectheader_(ptr);
    size_t oldsize = h->len;
    kit_ObjectHeader *nh = (kit_ObjectHeader*)S->alloc(S, h,
            sizeof(kit_ObjectHeader) + newsize*sizeof(void*),
            sizeof(kit_ObjectHeader) + oldsize*sizeof(void*));
    if (nh == NULL) kitG_outofmemory(S);
    nh->len = newsize;
    newptr = (void**)((kit_ObjectHeader*)nh+1);
    if (newsize > oldsize)
        memset(&newptr[oldsize], 0, newsize-oldsize);
    return newptr;
}

static void kitG_freearray(kit_State *S, void **ptr) {
    kit_ObjectHeader *h = kit_objectheader_(ptr);
    S->alloc(S, h, 0, sizeof(kit_ObjectHeader) + h->len*sizeof(void*));
}


/* kit object pool */

#define KIT_TOMBSTONE ((void*)~(uintptr_t)0)

static kit_Pool kitP_new      (kit_State *S, size_t size);
static void     kitP_delete   (kit_State *S, kit_Pool p);
static void   **kitP_ismarked (kit_Pool p, void *ptr);

KIT_API void kit_initpool(kit_Pool *p, size_t size)
{ *p = (size == 0) ? NULL : kitP_new(kit_state(), size); }

KIT_API void kit_freepool(kit_Pool *p)
{ kitP_delete(kit_state(), *p); *p = NULL; }

KIT_API int kit_ismarked(kit_Pool *p, void *ptr)
{ return kitP_ismarked(*p, ptr) ? 1 : 0; }

static kit_Pool kitP_new(kit_State *S, size_t size) {
    kit_PoolHeader *h;
    kit_Pool p;
    size = kitH_calcsize(size);
    h = (kit_PoolHeader*)S->alloc(S, NULL, sizeof(kit_PoolHeader) +
            size*sizeof(void*), 0);
    if (h == NULL) kitG_outofmemory(S);
    p = (void**)(h + 1);
    h->used = 0;
    h->n = size;
    memset(p, 0, size*sizeof(void*));
    return p;
}

static void kitP_delete(kit_State *S, kit_Pool p) {
    if (p != NULL) {
        kit_PoolHeader *h = kit_poolheader(&p);
        S->alloc(S, h, 0, sizeof(kit_PoolHeader) +
                h->n*sizeof(void*));
    }
}

static void **kitP_ismarked(kit_Pool p, void *ptr) {
    unsigned h = (unsigned)(uintptr_t)ptr;
    unsigned perturb, mask = kitH_calcmask(kit_poolsize(&p));
    void **v;
    if (ptr == NULL) return NULL;
    if (*(v = &p[h & mask]) == ptr)
        return v;
    for (perturb = h; *v != NULL; perturb >>= 5) {
        h = (h << 2u) + h + perturb + 1u;
        v = &p[h & mask];
        if (*v == ptr) return v;
    }
    return NULL;
}

KIT_API void kit_resizepool(kit_Pool *p, size_t size) {
    kit_State *S = kit_state();
    size_t i, oldsize = kit_poolsize(p);
    void **oldpool = *p;
    *p = kitP_new(S, size);
    for (i = 0; i < oldsize; ++i) {
        void *ptr = oldpool[i];
        if (ptr != NULL && ptr != KIT_TOMBSTONE)
            kit_mark_(p, ptr);
    }
    if (oldpool) kitP_delete(S, oldpool);
}

KIT_API size_t kit_mark_(kit_Pool *p, void *ptr) {
    unsigned mask, h = (unsigned)(uintptr_t)ptr, perturb;
    void **v;
    size_t len = kit_poolsize(p);
    if (kit_poolused(p) >= len)
        kit_resizepool(p, len + 1);
    len = kit_poolsize(p);
    mask = kitH_calcmask(len);
    v = &(*p)[h & mask];
    for (perturb = h; *v != NULL && *v != KIT_TOMBSTONE; perturb >>= 5) {
        h = (h << 2u) + h + perturb + 1u;
        v = &(*p)[h & mask];
        if (*v == ptr) return kit_poolheader(p)->used;
    }
    *v = ptr;
    return ++kit_poolheader(p)->used;
}

KIT_API size_t kit_unmark_(kit_Pool *p, void *ptr) {
    void **v = kitP_ismarked(*p, ptr);
    if (v) *v = KIT_TOMBSTONE;
    return --kit_poolheader(p)->used;
}

KIT_API size_t kit_sweeppool(kit_Pool *p) {
    size_t i, len = kit_poolsize(p);
    size_t sweeped = 0, removed = 0;
    for (i = 0; i < len; ++i) {
        void *ptr = (*p)[i];
        if (ptr == KIT_TOMBSTONE)
            ++removed;
        else if (ptr && kit_refcount(ptr) <= 0) {
            kit_delarray_(ptr);
            ++sweeped;
        }
        (*p)[i] = NULL;
    }
    kit_poolheader(p)->used = 0;
    if (removed + sweeped > (len >>= 1))
        kit_resizepool(p, len);
    return sweeped;
}

KIT_API size_t kit_clearpool(kit_Pool *p) {
    size_t i, len = kit_poolsize(p);
    size_t freed = 0;
    for (i = 0; i < len; ++i) {
        void *ptr = (*p)[i];
        /* we have own ways to cleanup objects of builtin types:
         *  - symbol type cleanup in its own pools
         *  - type type cleanup manually. */
        if (ptr && ptr != KIT_TOMBSTONE && (
                    kit_typeid_(ptr) != KIT_TIDX_SYMBOL &&
                    kit_typeid_(ptr) != KIT_TIDX_TYPE)) {
            kit_delarray_(ptr);
            ++freed;
        }
    }
    kit_freepool(p);
    return freed;
}

KIT_API int kit_nextpointer(kit_Pool *p, void ***pcur) {
    ptrdiff_t off;
    size_t i, len = kit_poolsize(p);
    void **pool = *p;
    if (pool == NULL) return 0;
    if (*pcur == NULL) i = 0;
    if ((off = *pcur - pool) < 0 || (size_t)off >= len)
        return 0;
    for (i = (size_t)off; i < len; ++i) {
        void **v = &pool[i];
        if (*v != NULL && *v != KIT_TOMBSTONE) {
            *pcur = *v;
            return 1;
        }
    }
    return 0;
}


/* kit object routines */

static void *kitO_h2ptr(kit_ObjectHeader *h)
{ return (void*)((kit_ObjectHeader*)h+1); }

static void *kitO_ptr2rawp(void *ptr, kit_Type *t)
{ return (void*)((char*)ptr - t->header_size); }

KIT_API int kit_isarray(void *ptr)
{ return kit_ismarked(&kit_state()->objects, ptr); }

static kit_ObjectHeader *kitO_rawp2h(void *rawp, kit_Type *t) {
    size_t header_offset;
    kit_assert(t->header_size >= sizeof(kit_ObjectHeader));
    header_offset = t->header_size - sizeof(kit_ObjectHeader);
    return (kit_ObjectHeader*)((char*)rawp + header_offset);
}

static int kitR_rangerelat(size_t len, int *pi, int *pj) {
    int i = *pi, j = *pj;
    if (i < 0) i += len;
    if (j < 0) j += len;
    if (i < 0 || (size_t)i >= len || j < 0 || (size_t)j >= len || i > j)
        return 0;
    *pi = i, *pj = j;
    return 1;
}

KIT_API void *kit_newrefarray(size_t sz) {
    kit_State *S = kit_state();
    void **refa = kitG_newarray(S, sz);
    kit_refcount_(refa) = 0;
    kit_mark_(&S->objects, (void*)refa);
    kit_mark_(&S->free_objects, (void*)refa);
    return refa;
}

static void *kitR_splicearray(void *ptr, int i, int j) {
    size_t len = kit_len_(ptr);
    int start;
    void **refa = (void**)ptr, **new_refa;
    if (!kitR_rangerelat(len, &i, &j)) return NULL;
    new_refa = (void**)kit_newrefarray(len);
    for (start = i; i <= j; ++i) {
        new_refa[i-start] = refa[i];
        kit_retain(refa[i]);
    }
    return (void*)new_refa;
}

static void *kitR_resizearray(void *ptr, size_t newsize) {
    size_t i, oldsize = kit_len_(ptr);
    void **refa = (void**)ptr, **new_refa;
    kit_assert(newsize < (KIT_MAX_SIZET-sizeof(kit_ObjectHeader))/sizeof(void*));
    for (i = newsize; i < oldsize; ++i)
        kit_release(refa[i]);
    new_refa = kitG_resizearray(kit_state(), ptr, newsize);
    return (void*)new_refa;
}

static void kitR_freearray(void *ptr) {
    kit_State *S = kit_state();
    size_t i, len = kit_len_(ptr);
    void **refa = (void**)ptr;
    if (S->objects != NULL)
        kit_unmark_(&S->objects, ptr);
    for (i = 0; i < len; ++i)
        if (refa[i] != NULL)
            kit_release(refa[i]);
    kitG_freearray(S, ptr);
}

KIT_API void *kit_newarray_(kit_Type *t, size_t sz) {
    if (t->type_id == KIT_TIDX_REF)
        return kit_newrefarray(sz);
    else {
        kit_State *S = kit_state();
        void *ptr;
        size_t rawsize = t->header_size + sz*t->obj_size;
        void *rawp = t->alloc(S, NULL, rawsize, (size_t)t->type_id);
        kit_ObjectHeader *h = kitO_rawp2h(rawp, t);
        if (rawp == NULL) kitG_outofmemory(S);
        KIT_DEBUG_STMT(t->instances++);
        h->type_id = t->type_id;
        h->ref = 0;
        h->len = sz;
        ptr = kitO_h2ptr(h);
        kit_mark_(&S->objects, ptr);
        kit_mark_(&S->free_objects, ptr);
        if (t->init_object) t->init_object(t, ptr);
        return ptr;
    }
}

KIT_API void *kit_splicearray_(void *ptr, int i, int j) {
    if (kit_typeid_(ptr) == KIT_TIDX_REF)
        return kitR_splicearray(ptr, i, j);
    else {
        kit_Type *t = kit_objecttype_(ptr);
        size_t len = kit_len_(ptr);
        void *newptr;
        if (!kitR_rangerelat(len, &i, &j)) return NULL;
        newptr = kit_newarray_(t, len);
        memcpy(newptr, (char*)ptr + i*t->obj_size, len*t->obj_size);
        return newptr;
    }
}

KIT_API void *kit_resizearray_(void *ptr, size_t sz) {
    if (kit_typeid_(ptr) == KIT_TIDX_REF)
        return kitR_resizearray(ptr, sz);
    else {
        kit_ObjectHeader *h;
        kit_State *S = kit_state();
        kit_Type *t = kit_objecttype_(ptr);
        size_t oldrs, newrs;
        void *rawp;
        kit_assert(sz < (KIT_MAX_SIZET-t->header_size)/t->obj_size);
        oldrs = t->header_size + kit_len_(ptr)*t->obj_size;
        newrs = t->header_size + sz*t->obj_size;
        rawp = t->alloc(S, kitO_ptr2rawp(ptr, t), newrs, oldrs);
        kit_assert(rawp != NULL || newrs > oldrs);
        if (rawp == NULL) kitG_outofmemory(S);
        h = kitO_rawp2h(rawp, t);
        h->len = sz;
        return kitO_h2ptr(h);
    }
}

KIT_API void kit_delarray_(void *ptr) {
    if (kit_typeid_(ptr) == KIT_TIDX_REF)
        kitR_freearray(ptr);
    else {
        kit_State *S = kit_state();
        kit_Type *t = kit_objecttype_(ptr);
        size_t len = kit_len_(ptr);
        size_t oldsize = t->header_size + len*t->obj_size;
        if (S->objects != NULL)
            kit_unmark_(&S->objects, ptr);
        if (t->drop_object) t->drop_object(t, ptr);
        t->alloc(S, kitO_ptr2rawp(ptr, t), 0, oldsize);
        KIT_DEBUG_STMT(t->instances--);
    }
}

KIT_API int kit_static_(void *ptr) {
    kit_unmark_(&kit_state()->free_objects, ptr);
    kit_objectheader_(ptr)->ref = KIT_STAIC_OBJECT;
    return KIT_STAIC_OBJECT;
}

KIT_API int kit_retain_(void *ptr) {
    kit_ObjectHeader *h = kit_objectheader_(ptr);
    if (h->ref == 0)
        kit_unmark_(&kit_state()->free_objects, ptr);
    kit_assert(h->ref == KIT_STAIC_OBJECT || h->ref < KIT_MAX_REFCOUNT);
    if (h->ref != KIT_STAIC_OBJECT) ++h->ref;
    return h->ref;
}

KIT_API int kit_release_(void *ptr) {
    kit_State *S = kit_state();
    kit_ObjectHeader *h = kit_objectheader_(ptr);
    if (h->ref == 1)
        kit_mark_(&S->free_objects, ptr);
    kit_assert(h->ref == KIT_STAIC_OBJECT || h->ref > -KIT_MAX_REFCOUNT);
    if (h->ref != KIT_STAIC_OBJECT) --h->ref;
    return h->ref;
}

KIT_API void kit_retain_all_(void *ptr) {
    size_t i, len = kit_len_(ptr);
    if (kit_typeid_(ptr) == KIT_TIDX_REF) {
        void **refa = (void**)ptr;
        for (i = 0; i < len; ++i)
            kit_safe_retain(refa[i]);
    }
}

KIT_API void kit_release_all_(void *ptr) {
    size_t i, len = kit_len_(ptr);
    if (kit_typeid_(ptr) == KIT_TIDX_REF) {
        void **refa = (void**)ptr;
        for (i = 0; i < len; ++i)
            kit_safe_release(refa[i]);
    }
}

static void kitO_init(kit_State *S) {
    S->free_objects = kitP_new(S, KIT_MIN_OBJPOOL_SIZE);
    S->objects = kitP_new(S, KIT_MIN_OBJPOOL_SIZE);
}

static void kitO_cleanup(kit_State *S) {
    kit_Pool objects = S->objects;
    S->objects = NULL; /* avoid unmark objects */
    kitP_delete(S, S->free_objects);
    kit_clearpool(&objects);
    kitP_delete(S, objects);
}


/* kit symbol routines */

static unsigned kitS_calchash(const char *s, size_t len, unsigned seed);

KIT_API kit_Symbol *kit_symbol(const char *str)
{ return kit_lsymbol(str, strlen(str)); }

KIT_API unsigned kit_calchash(const char *s, size_t len)
{ return kitS_calchash(s, len, kit_state()->seed); } 

static unsigned kitS_calchash(const char *s, size_t len, unsigned seed) {
    unsigned h = seed ^ (unsigned)len;
    size_t l1;
    size_t step = (len >> KIT_HASHLIMIT) + 1;
    for (l1 = len; l1 >= step; l1 -= step)
        h = h ^ ((h<<5) + (h>>2) + (unsigned char)(s[l1 - 1]));
    return h;
}

static void kitS_initpool(kit_State *S, kit_SymbolPool *p, size_t size) {
    p->hash = (kit_SymbolHeader**)kitG_newarray(S, size);
    p->n = 0;
}

static void kitS_resize(kit_State *S, kit_SymbolPool *p, size_t size) {
    size_t i, oldsize = kit_len_(p->hash);
    unsigned mask;
    size = kitH_calcsize(size);
    if (size > oldsize) p->hash =
        (kit_SymbolHeader**)kitG_resizearray(S, (void**)p->hash, size);
    /* rehash */
    mask = (unsigned)(size - 1u);
    for (i = 0; i < oldsize; ++i) {
        kit_SymbolHeader *s = p->hash[i];
        p->hash[i] = NULL;
        while (s) { /* for each node in the list */
            kit_SymbolHeader *next = s->next; /* save next */
            size_t idx = s->hash & mask;
            s->next = p->hash[idx];
            p->hash[idx] = s;
            s = next;
        }
    }
    if (size < oldsize) { /* shrinking slice must be empty */
        kit_assert(p->hash[size] == NULL && p->hash[oldsize - 1] == NULL);
        p->hash = (kit_SymbolHeader**)kitG_resizearray(S,
                (void**)p->hash, size);
    }
}

static kit_SymbolHeader **kitS_find(kit_SymbolPool *p, const char *str, size_t len, unsigned hash) {
    unsigned mask = kitH_calcmask(kit_len_(p->hash));
    kit_SymbolHeader **list = &p->hash[hash & mask];
    while ((*list) != NULL) {
        if (memcmp((char*)(*list) + sizeof(kit_SymbolHeader), str, len) == 0)
            return list;
        list = &(*list)->next;
    }
    return NULL;
}

static kit_Symbol *kitS_new(kit_SymbolPool *p, const char *str, size_t len, unsigned hash) {
    unsigned mask = kitH_calcmask(kit_len_(p->hash));
    kit_SymbolHeader *h, **list = &p->hash[hash & mask];
    char *sym = (char*)kit_newarray_(KIT_TP(SYMBOL), len+1);
    memcpy(sym, str, len);
    sym[len] = '\0';
    if (kit_len_(p->hash) < p->n)
        kitS_resize(kit_state(), p, p->n + 1);
    h = kit_symbolheader_(sym);
    h->hash = hash;
    h->next = *list;
    *list = h;
    ++p->n;
    return (kit_Symbol*)(h+1);
}

static size_t kitS_delete(kit_SymbolPool *p, kit_Symbol *s) {
    kit_SymbolHeader *h = kit_symbolheader_(s);
    kit_SymbolHeader **v = kitS_find(p, (const char*)s,
            h->h.len-1, h->hash);
    if (v && *v == h) {
        *v = (*v)->next; /* delete symbol from table */
        return --p->n;
    }
    kit_assert(!"symbol s not in pool!");
    return p->n;
}

KIT_API kit_Symbol *kit_lsymbol(const char *str, size_t len) {
    kit_State *S = kit_state();
    kit_SymbolPool *p = &S->symbols;
    unsigned hash = kitS_calchash(str, len, S->seed);
    kit_SymbolHeader **h = kitS_find(p, str, len, hash);
    if (h) return (kit_Symbol*)(*h + 1);
    return kitS_new(p, str, len, hash);
}

KIT_API kit_Symbol *kit_symbols(size_t idx) {
    kit_State *S = kit_state();
    kit_Symbol *sym;
    if (idx > S->type_count) return NULL;
    sym = S->types[idx]->name;
    kit_assert(sym != NULL);
    return sym;
}

static void kitS_initbuiltin(kit_State *S, unsigned idx, const char *s, size_t len) {
    unsigned hash = kitS_calchash(s, len, S->seed);
    kit_Symbol *sym = kitS_new(&S->symbols, s, len, hash);
    kit_refcount_(sym) = KIT_STAIC_OBJECT;
    S->builtin_types[idx].name = sym;
    kit_settable(&S->typemap, sym)->value =
        &S->builtin_types[idx];
}

static void kitS_init(kit_State *S) {
    kit_State *old = kit_setstate(S);
    kitS_initpool(S, &S->symbols, KIT_MIN_SYMTABLE_SIZE);
    kit_inittable(&S->typemap, KIT_MIN_TYPETAB_SIZE);
#define X(T,sym,os,h) \
    kitS_initbuiltin(S, KIT_TIDX_##T, "" sym, sizeof(sym)-1);
    KIT_BUILTIN_TYPES(X)
#undef  X
    kit_setstate(old);
}

static void kitS_cleanup(kit_State *S) {
    kit_SymbolHeader **hash = S->symbols.hash;
    size_t i, size = kit_len_(hash);
    for (i = 0; i < size; ++i) {
        kit_SymbolHeader *h = hash[i];
        while (h != NULL) {
            kit_SymbolHeader *next = h->next;
            kit_delarray_((void*)(h+1));
            h = next;
        }
    }
    kitG_freearray(S, (void**)hash);
}


/* kit table routines */

static kit_Table kitH_new    (kit_State *S, size_t size);
static void      kitH_delete (kit_State *S, kit_Table t);

static unsigned kitH_calcmask(size_t len)
{ kit_assert((len&(len-1)) == 0); return len - 1; }

KIT_API void kit_inittable(kit_Table *t, size_t size)
{ *t = (size == 0) ? NULL : kitH_new(kit_state(), size); }

KIT_API void kit_freetable(kit_Table *t)
{ kit_resettable(t); kitH_delete(kit_state(), *t); *t = NULL; }

static size_t kitH_calcsize(size_t size) {
    size_t realsize = 2;
    if (size == 0) return 0;
    while (realsize < KIT_MAX_SIZET/2 && realsize < size)
        realsize <<= 1;
    return realsize;
}

static unsigned kitH_calchash(void *key) {
    if (kit_typeid_(key) == KIT_TIDX_SYMBOL)
        return kit_symbolhash_(key);
    return (unsigned)(uintptr_t)key;
}

static kit_Entry *getfreepos(kit_TableHeader *h, kit_Entry *hash) {
    while (h->lastfree > hash) {
        h->lastfree--;
        if (h->lastfree->key == NULL && h->lastfree->next == NULL)
            return h->lastfree;
    }
    return NULL;  /* could not find a free place */
}

static kit_Entry *getnewentry(kit_Table *t, void *key) {
    kit_TableHeader *h = kit_tableheader(t);
    kit_Entry *hash = *t;
    size_t len = kit_tablesize(t);
    unsigned mask = kitH_calcmask(len);
    kit_Entry *mp;
    if (key == NULL) return NULL;
    mp = &hash[kitH_calchash(key) & mask];
    if (mp == NULL || mp->key != NULL) { /* main position is taken? */
        kit_Entry *othern;
        kit_Entry *n = getfreepos(h, hash); /* get a free place */
        if (n == NULL) { /* can not find a free place? */
            kit_resizetable(t, len+1); /* grow table */
            return getnewentry(t, key);
        }
        othern = &hash[kitH_calchash(mp->key) & mask];
        if (othern != mp) { /* is colliding node out of its main position? */
            /* yes; move colliding node into free position */
            while (othern->next != mp) othern = othern->next; /* find previous */
            othern->next = n; /* redo the chain whth `n' in place of `mp' */
            *n = *mp; /* copy colliding node into free pos (mp->next also goes) */
            mp->next = NULL; /* now `mp' is free */
        }
        else { /* colliding node is in its own main position */
            /* new node will go into free position */
            n->next = mp->next;
            mp->next = n;
            mp = n;
        }
    }
    kit_retain(key); /* checked */
    mp->key = key;
    mp->value = NULL;
    return mp;
}

static kit_Table kitH_new(kit_State *S, size_t size) {
    kit_TableHeader *h;
    kit_Table t;
    size = kitH_calcsize(size);
    h = (kit_TableHeader*)S->alloc(S, NULL, sizeof(kit_TableHeader) +
            size*sizeof(kit_Entry), 0);
    if (h == NULL) kitG_outofmemory(S);
    t = (kit_Entry*)(h + 1);
    h->lastfree = &t[size - 1];
    h->n = size;
    memset(t, 0, size*sizeof(kit_Entry));
    return t;
}

static void kitH_delete(kit_State *S, kit_Table t) {
    if (t != NULL) {
        kit_TableHeader *h = kit_tableheader(&t);
        S->alloc(S, h, 0, sizeof(kit_TableHeader) +
                h->n*sizeof(kit_Entry));
    }
}

KIT_API void kit_resettable(kit_Table *t) {
    size_t i, len;
    kit_Entry *hash = *t;
    if (hash == NULL) return;
    for (i = 0, len = kit_tablesize(t); i < len; ++i) {
        kit_Entry *e = &hash[i];
        if (e->key)   kit_release(e->key);   /* checked */
        if (e->value) kit_release(e->value); /* checked */
        e->next = NULL;
        e->key = NULL;
        e->value = NULL;
    }
    kit_tableheader(t)->lastfree = &hash[len-1];
}

KIT_API void kit_resizetable(kit_Table *t, size_t sz) {
    kit_Table oldt = *t;
    size_t i, oldsize = kit_tablesize(&oldt);
    kit_inittable(t, sz);
    if (*t == NULL || oldt == NULL) return;
    for (i = 0; i < oldsize; ++i) {
        if (oldt[i].key != NULL) {
            kit_Entry *e = kit_settable(t, oldt[i].key);
            e->value = oldt[i].value;
        }
    }
    kitH_delete(kit_state(), oldt);
}

KIT_API size_t kit_counttable(kit_Table *t) {
    size_t i, count = 0;
    kit_Entry *hash = *t;
    size_t size = kit_tablesize(t);
    for (i = 0; i < size; ++i)
        if (hash[i].key != NULL)
            ++count;
    return count;
}

KIT_API kit_Entry *kit_gettable(kit_Table *t, void *key) {
    kit_Entry *e, *hash = *t;
    if (hash == NULL || key == NULL) return NULL;
    e = &hash[kitH_calchash(key) & kitH_calcmask(kit_tablesize(t))];
    while (e->key != key && e->next != NULL)
        e = e->next;
    return e->key != key ? NULL : e;
}

KIT_API kit_Entry *kit_settable(kit_Table *t, void *key) {
    kit_Entry *e;
    if (key == NULL) return NULL;
    if (*t == NULL) kit_resizetable(t, KIT_MIN_TABLE_SIZE);
    if ((e = kit_gettable(t, key)) != NULL) return e;
    kit_assert(*t != NULL);
    return getnewentry(t, key);
}

KIT_API void kit_delentry (kit_Entry *e) {
    if (e == NULL) return;
    if (e->key != NULL) {
        kit_release(e->key); /* checked */
        e->key = NULL;
    }
    if (e->value != NULL)
        kit_release(e->value); /* checked */
    e->value = NULL;
}

KIT_API int kit_nextentry_(kit_Table *t, kit_Entry **pcur) {
    ptrdiff_t off;
    size_t i, len = kit_tablesize(t);
    kit_Entry *hash = *t;
    if (hash == NULL) return 0;
    if (*pcur == NULL) i = 0;
    if ((off = *pcur - hash) < 0 || (size_t)off >= len)
        return 0;
    for (i = (size_t)off; i < len; ++i) {
        kit_Entry *e = &hash[i];
        if (e->key != NULL) {
            *pcur = e;
            return 1;
        }
    }
    return 0;
}


/* kit type routines */

static void kitT_removesymbol(kit_Type *t, void *ptr)
{ (void)t; kitS_delete(&kit_state()->symbols, (kit_Symbol*)ptr); }

static void kitT_inittype(kit_State *S, kit_Type *t) {
    t->name = NULL;
    t->alloc = S->alloc;
    t->init_object = NULL;
    t->drop_object = NULL;
    t->close_type = NULL;
    t->type_id = -1;
    t->header_size = sizeof(kit_ObjectHeader);
    t->obj_size = 1;
    t->instances = 0;
}

static unsigned kitT_gentypeid(kit_State *S, kit_Type *t) {
    size_t len = kit_len_(S->types);
    if (len == S->type_count)
        S->types = (kit_Type**)kitG_resizearray(S, (void**)S->types, len*2);
    S->types[S->type_count] = t;
    return S->type_count++;
}

KIT_API kit_Type *kit_newtype_(kit_Symbol *name, size_t sz) {
    kit_State *S = kit_state();
    kit_Entry *entry = kit_settable(&S->typemap, name);
    kit_Type *type;
    if (entry->value != NULL)
        return (kit_Type*)entry->value;
    if (sz == 0) sz = sizeof(kit_Type);
    kit_assert(sz >= sizeof(kit_Type));
    type = kit_newarray_(KIT_TP(TYPE), sz);
    kit_refcount_(type) = KIT_STAIC_OBJECT;
    kitT_inittype(S, type);
    entry->value = type;
    type->name = name;
    type->type_id = kitT_gentypeid(S, type);
    kit_retain_(name);
    return type;
}

KIT_API kit_Type *kit_ctype_(kit_Symbol *name, size_t sz) {
    kit_Type *t = kit_newtype_(name, 0);
    kit_assert(t->obj_size == 1 || t->obj_size == sz);
    t->obj_size = sz;
    return t;
}

KIT_API kit_Type *kit_type_(kit_Symbol *name) {
    kit_State *S = kit_state();
    kit_Entry *entry = kit_gettable(&S->typemap, name);
    return entry == NULL ? NULL : (kit_Type*)entry->value;
}

KIT_API kit_Type *kit_typebyid(unsigned type_id) {
    kit_State *S = kit_state();
    return type_id <= S->type_count ? S->types[type_id] : NULL;
}

static void kitT_initbuitin(kit_State *S,
        unsigned idx, size_t os, size_t hs) {
    kit_Type *t = &S->builtin_types[idx];
    kitT_inittype(S, t);
    t->type_id = idx;
    t->header_size = hs;
    t->obj_size = os;
    S->types[idx] = t;
}

static void kitT_init(kit_State *S) {
    kit_assert(KIT_MIN_TYPETAB_SIZE >= KIT_TIDX_COUNT);
    S->types = (kit_Type**)kitG_newarray(S, KIT_MIN_TYPETAB_SIZE);
#define X(T,sym,os,h) \
    kitT_initbuitin(S, KIT_TIDX_##T, os, sizeof(h));
    KIT_BUILTIN_TYPES(X)
#undef  X
    S->type_count = KIT_TIDX_COUNT;
    S->types[KIT_TIDX_SYMBOL]->drop_object = kitT_removesymbol;
}

static void kitT_cleanup(kit_State *S) {
    size_t i = S->type_count - 1;
    /* remaining a table: typemap */
    do {
        kit_Type *t = S->types[i];
        KIT_DEBUG_STMT(kit_assert(t->instances == 0));
        t->name = NULL; /* symbols has freed */
        if (t->close_type) t->close_type(t);
        if (i >= KIT_TIDX_COUNT || t != &S->builtin_types[i])
            kit_delarray_(t);
    } while (i-- > 0);
    kitG_freearray(S, (void*)S->types);
    kitH_delete(S, S->typemap);
}

static void kitT_initptr(kit_Type *t, void *ptr) {
    void **ps = (void**)ptr;
    size_t i, len = kit_len_(ptr);
    for (i = 0; i < len; ++i)
        ps[i] = NULL;
}

static void kitT_droppool(kit_Type *t, void *ptr) {
    kit_Pool *p = (kit_Pool*)ptr;
    size_t i, len = kit_len_(ptr);
    for (i = 0; i < len; ++i)
        kit_freepool(&p[i]);
}

static void kitT_droptable(kit_Type *t, void *ptr) {
    kit_Table *ts = (kit_Table*)ptr;
    size_t i, len = kit_len_(ptr);
    for (i = 0; i < len; ++i)
        kit_freetable(&ts[i]);
}

static void kitT_opentypes(kit_State *S) {
    kit_Type *t;
    t = kit_newtype("kit_Table", 0);
    t->obj_size = sizeof(kit_Table);
    t->init_object = kitT_initptr;
    t->drop_object = kitT_droptable;
    t = kit_newtype("kit_Pool", 0);
    t->obj_size = sizeof(kit_Pool);
    t->init_object = kitT_initptr;
    t->drop_object = kitT_droppool;
}


/* kit global state */

#define KIT_DS(S) ((S)?(S):kit_state())

KIT_API void kit_setpanicf(kit_State *S, kit_Panic *panicf, void *ud)
{ S=KIT_DS(S); S->panic = panicf; S->panic_ud = ud; }

KIT_API kit_Panic *kit_getpanicf(kit_State *S, void **pud)
{ S=KIT_DS(S); if (pud) *pud = S->panic_ud; return S->panic; }

KIT_API size_t kit_totalmem(kit_State *S)
{ S=KIT_DS(S); return S->totalmem; }

static void kitG_closedef(void) {
    if (kit_default_state != NULL) {
        kit_close(kit_default_state);
        kit_assert(kit_default_state == NULL);
    }
}

static kit_State *kitG_defstate(void) {
    if (kit_default_state == NULL) {
        kit_default_state = kit_newstate(NULL);
        atexit(kitG_closedef);
    }
    return kit_default_state;
}

KIT_API kit_State *kit_state(void) {
    if (kit_current_state == NULL)
        kit_current_state = kitG_defstate();
    return kit_current_state;
}

KIT_API kit_State *kit_setstate(kit_State *S) {
    kit_State *old = kit_current_state;
    kit_current_state = KIT_DS(S);
    return old;
}

KIT_API kit_State *kit_newstate(kit_Alloc *allocf) {
    kit_State *S = (kit_State*)malloc(sizeof(kit_State));
    if (S == NULL) return NULL;
    S->alloc = allocf == NULL ? kitG_alloc : allocf;
    S->totalmem = 0;
    S->panic = NULL;
    S->panic_ud = NULL;
    S->seed = (unsigned)(uintptr_t)S;
    S->types = NULL;
    S->type_count = 0;
    /* set current state to self */ {
        kit_State *oldS = kit_setstate(S);
        kitO_init(S);
        kitT_init(S);
        kitS_init(S);
        kitT_opentypes(S);
        kit_setstate(oldS);
    }
    return S;
}

KIT_API size_t kit_sweep(kit_State *S) {
    size_t freed;
    kit_State *oldS = kit_setstate(S);
    freed = kit_sweeppool(&kit_state()->free_objects);
    kit_setstate(oldS);
    return freed;
}

KIT_API void kit_panic(kit_State *S, const char *msg) {
    S = KIT_DS(S);
    if (S->panic)
        S->panic(S, msg, S->panic_ud);
    else
        fprintf(stderr, "kit: %s\n", msg);
    abort();
}

KIT_API void kit_close(kit_State *S) {
    kit_State *oldS = kit_setstate(S);
    S = kit_state();
    kitO_cleanup(S);
    kitS_cleanup(S);
    kitT_cleanup(S);
    kit_setstate(oldS);
    KIT_DEBUG_STMT(kit_assert(S->totalmem == 0));
    if (S == kit_current_state)
        kit_current_state = NULL;
    if (S == kit_default_state)
        kit_default_state = NULL;
    free(S);
}


KIT_NS_END

#endif /* KIT_IMPLEMENTATION */
/* cc: flags+='-DKIT_DEBUG -DKIT_IMPLEMENTATION'
 * cc: flags+='-mdll -s -O3 -xc' output='kit.dll' */
