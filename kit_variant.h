#ifndef kit_variant_h
#define kit_variant_h


#include <stddef.h>


#ifndef KIT_NS_BEGIN
# ifdef __cplusplus
#   define KIT_NS_BEGIN extern "C" {
#   define KIT_NS_END   }
# else
#   define KIT_NS_BEGIN
#   define KIT_NS_END
# endif
#endif /* KIT_NS_BEGIN */

#ifndef KIT_INLINE
/* these should support C99's inline */
/* the test for __POCC__ has to come before the test for _MSC_VER,
   because PellesC defines _MSC_VER too. This is brain-dead. */
# if defined(__GNUC__) || defined(__LCC__) || defined(__POCC__) \
                      || defined(__TINYC__)
#   define KIT_INLINE(rettype, name) static inline rettype name
/* Borland's compiler is really STRANGE here; note that the __fastcall
   keyword cannot be before the return type, but __inline cannot be after
   the return type. */
# elif defined(__BORLANDC__) || defined(_MSC_VER)
#   define KIT_INLINE(rettype, name) static __inline rettype name
# elif defined(__DMC__)
#   define KIT_INLINE(rettype, name) static inline rettype name
# elif defined(__WATCOMC__)
#   define KIT_INLINE(rettype, name) static __inline rettype name
# else /* others are less picky: */
#   define KIT_INLINE(rettype, name) static rettype __inline name
# endif
#endif /* KIT_INLINE */


/* Define int32_t, int64_t, and uint64_t types for UST/MSC */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
# include <inttypes.h>
#elif defined(__sun__) || defined(__digital__)
# include <inttypes.h>
# if defined(__STDC__)
#   if defined(__arch64__) || defined(_LP64)
typedef long int int64_t;
typedef unsigned long int uint64_t;
#   else
typedef long long int int64_t;
typedef unsigned long long int uint64_t;
#   endif /* __arch64__ */
# endif /* __STDC__ */
#elif defined( __VMS ) || defined(__sgi)
# include <inttypes.h>
#elif defined(__SCO__) || defined(__USLC__)
# include <stdint.h>
#elif defined(__UNIXOS2__) || defined(__SOL64__)
typedef long int int32_t;
typedef long long int int64_t;
typedef unsigned long long int uint64_t;
#elif defined(_WIN32) && defined(__GNUC__)
# include <stdint.h>
#elif defined(_WIN32)
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
/* Fallback if nothing above works */
# include <inttypes.h>
#endif


KIT_NS_BEGIN

/* basic types for kit variants */

#define KIT_VARIANT_TYPES(X)              \
 /* X(NAME,     type,         name    ) */\
 /* X(NIL,      void,         nil     ) */\
    X(INT,      kit_Int,      int     )   \
    X(INTEGER,  kit_Integer,  integer )   \
    X(NUMBER,   kit_Number,   number  )   \
    X(POINTER,  void*,        ptr     )   \
    X(FUNCPTR,  kit_Funcptr,  fptr    )   \
    X(POINT,    kit_Point,    point   )   \
    X(SIZE,     kit_Size,     size    )   \
    X(BUFFER,   kit_Buffer,   buffer  )   \
    X(STATE,    kit_State*,   state   )   \
    X(TYPE,     kit_Type*,    type    )   \
    X(OBJECT,   void*,        object  )   \
    X(REFS,     void*,        refs    )   \
    X(SYMBOL,   kit_Symbol*,  symbol  )   \
    X(TABLE,    kit_Table,    table   )   \
    X(POOL,     kit_Pool,     pool    )   \

typedef enum kit_VarType {
    KIT_VNIL,
#define X(NAME,t,n) KIT_V##NAME,
    KIT_VARIANT_TYPES(X)
#undef  X
    KIT_VARTYPE_COUNT
} kit_VarType;

typedef unsigned char kit_Byte;
typedef int32_t       kit_Int;
typedef int64_t       kit_Integer;
typedef double        kit_Number;
typedef void        (*kit_Funcptr) (void);

#ifndef kit_h
typedef struct kit_State  kit_State;
typedef struct kit_Type   kit_Type;
typedef struct kit_Symbol kit_Symbol;
typedef struct kit_Entry *kit_Table;
typedef void*            *kit_Pool;
#endif /* kit_h */

typedef struct kit_Point {
    float x, y;
} kit_Point;

typedef struct kit_Size {
    float width, height;
} kit_Size;

typedef struct kit_Buffer {
    size_t len;
    kit_Byte *p;
} kit_Buffer;

typedef union kit_Variant {
    int type;
    int idx;
    union {
#define X(NAME,type,name) type v##name;
    KIT_VARIANT_TYPES(X)
#undef  X
    };
} kit_Variant;


/* helper routines */

KIT_INLINE(kit_Point, kit_point) (float x, float y) {
    kit_Point pt;
    pt.x = x, pt.y = y;
    return pt;
}

KIT_INLINE(kit_Size, kit_size) (float width, float height) {
    kit_Size sz;
    sz.width = width, sz.height = height;
    return sz;
}

KIT_INLINE(kit_Buffer, kit_buffer) (char *p, size_t len) {
    kit_Buffer b;
    b.p = (kit_Byte*)p, b.len = len;
    return b;
}


/* variant routines */

KIT_INLINE(int, kit_isnil) (kit_Variant *v)
{ return v->type == KIT_VNIL; }

KIT_INLINE(kit_Variant, kit_vnil) (void)
{ kit_Variant v = { KIT_VNIL }; return v; }

#define DECLARE_VARFUNC(TYPE, type, name)             \
KIT_INLINE(kit_Variant, kit_v##name) (type v##name) { \
    kit_Variant v = { KIT_V##TYPE };                  \
    v.v##name = v##name; return v;                  }
KIT_VARIANT_TYPES(DECLARE_VARFUNC)
#undef  DECLARE_VARFUNC

KIT_INLINE(kit_Variant, kit_vp) (float x, float y) {
    kit_Variant v = { KIT_VPOINT };
    v.vpoint.x = x, v.vpoint.y = y;
    return v;
}

KIT_INLINE(kit_Variant, kit_vs) (float width, float height) {
    kit_Variant v = { KIT_VSIZE };
    v.vsize.width = width, v.vsize.height = height;
    return v;
}

KIT_INLINE(kit_Variant, kit_vbuff) (char *buff, size_t len) {
    kit_Variant v = { KIT_VSIZE };
    v.vbuffer.p = (kit_Byte*)buff, v.vbuffer.len = len;
    return v;
}


KIT_NS_END

#endif /* kit_variant_h */
