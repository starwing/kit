#ifndef kit_list_h
#define kit_list_h


#ifndef KIT_NEXT
# define KIT_NEXT next
#endif

#ifndef KIT_PREV
# define KIT_PREV prev
#endif

#ifndef KIT_PPREV
# define KIT_PPREV pprev
#endif

/* === double linked list === */

#define kitL_init(q)   ((void)((q)->KIT_PREV = (q), (q)->KIT_NEXT = (q)))
#define kitL_empty(h)  ((h) == (h)->KIT_PREV)

#define kitL_sentinel(h) (h)
#define kitL_first(h)    ((h)->KIT_NEXT)
#define kitL_last(h)     ((h)->KIT_PREV)
#define kitL_next(q)     ((q)->KIT_NEXT)
#define kitL_prev(q)     ((q)->KIT_PREV)

#define kitL_insert(h, x) ((void)(                                            \
    (x)->KIT_PREV = (h)->KIT_PREV,                                            \
    (x)->KIT_PREV->KIT_NEXT = (x),                                            \
    (x)->KIT_NEXT = (h),                                                      \
    (h)->KIT_PREV = (x)))

#define kitL_insert_pointer(p, x) ((void)(                                    \
    (p) != NULL ? kitL_insert(p, x) :                                         \
    ( (p) = (x), kitL_init(x) )))

#define kitL_remove(x) ((void)(                                               \
    (x)->KIT_NEXT->KIT_PREV = (x)->KIT_PREV,                                  \
    (x)->KIT_PREV->KIT_NEXT = (x)->KIT_NEXT))

#define kitL_remove_init(x) ((void)(                                          \
    (x)->KIT_NEXT->KIT_PREV = (x)->KIT_PREV,                                  \
    (x)->KIT_PREV->KIT_NEXT = (x)->KIT_NEXT,                                  \
    (x)->KIT_PREV = (x),                                                      \
    (x)->KIT_NEXT = (x)))

#define kitL_split(h, q, n) ((void)(                                          \
    (n)->KIT_PREV = (h)->KIT_PREV,                                            \
    (n)->KIT_PREV->KIT_NEXT = (n),                                            \
    (n)->KIT_NEXT = (q),                                                      \
    (h)->KIT_PREV = (q)->KIT_PREV,                                            \
    (h)->KIT_PREV->KIT_NEXT = (h),                                            \
    (q)->KIT_PREV = n))

#define kitL_merge(h, n) ((void)(                                             \
    (h)->KIT_PREV->KIT_NEXT = (n)->KIT_NEXT,                                  \
    (n)->KIT_NEXT->KIT_PREV = (h)->KIT_PREV,                                  \
    (h)->KIT_PREV = (n)->KIT_PREV,                                            \
    (h)->KIT_PREV->KIT_NEXT = (h)))

#define kitL_foreach(i, h)                                                    \
    for ((i) = (h)->KIT_NEXT; (i) != (h); (i) = (i)->KIT_NEXT)

#define kitL_foreach_back(i, h)                                               \
    for ((i) = (h)->KIT_PREV; (i) != (h); (i) = (i)->KIT_PREV)

#define kitL_foreach_safe(i, nexti, h)                                        \
    for ((i) = (h)->KIT_NEXT, (nexti) = (i)->KIT_NEXT;                        \
         (i) != (h);                                                          \
         (i) = (nexti), (nexti) = (nexti)->KIT_NEXT)


/* === half(hash) list === */

#define kitHL_init(h, x) ((void)(                                             \
            (x)->KIT_PPREV = &(h),                                            \
            (x)->KIT_NEXT  = (h),                                             \
            (void)((h) && ((h)->KIT_PPREV = &(x)->KIT_NEXT)),                 \
            (h) = (x)))

#define kitHL_remove(x) ((void)(                                              \
            *(x)->KIT_PPREV = (x)->KIT_NEXT,                                  \
            (void)((x)->KIT_NEXT && ((x)->KIT_NEXT->KIT_PPREV = (x)->KIT_PPREV))))

#define kitHL_insert(h, x) ((void)(kitHL_remove(x), kitHL_init(h, x)))


#endif /* kit_list_h */
