#define KIT_DEBUG
#define KIT_IMPLEMENTATION
#include "kit.h"
#include "kit_variant.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    kit_Table *t = kit_newobject(kit_Table);
    kit_retain_(t);
    assert(*t == NULL);

    /* test symbol */ {
        int sym_count = KIT_TP(SYMBOL)->instances;
        kit_Symbol *foo = kit_symbol("foo");
        kit_Symbol *bar = kit_symbol("bar");
        assert(kit_calchash("foo", 3) == kit_symbolhash(foo));
        assert(kit_calchash("bar", 3) == kit_symbolhash(bar));
        assert(sym_count + 2 == KIT_TP(SYMBOL)->instances);
        assert(foo != bar);
        assert(foo == kit_symbol("foo"));
        assert(sym_count + 2 == KIT_TP(SYMBOL)->instances);
        assert(kit_refcount(foo) == 0);
        assert(kit_refcount(bar) == 0);
        kit_sweep(NULL);
        assert(sym_count == KIT_TP(SYMBOL)->instances);
    }

    /* test array */ {
        float *farray = kit_newobjects(float, 5);
        assert(farray != NULL);
        assert(!kit_isarray(NULL));
        assert(kit_isarray(farray));
        assert(kit_type(float));
        assert(kit_type(float) == kit_type(float));
        assert(strcmp((const char*)kit_type(float)->name, "float") == 0);
        assert(kit_type(float)->obj_size == sizeof(float));
        assert(kit_type(float)->instances == 1);

        assert(kit_objecttype(farray) == kit_type(float));
        assert(kit_refcount(farray) == 0);
        assert(kit_len(farray) == 5);

        farray[0] = 10;
        farray[4] = 20;
        kit_retain(farray);
        assert(kit_refcount(farray) == 1);
        kit_release(farray);
        assert(kit_refcount(farray) == 0);
        kit_setfield(t, "foo", farray);
        assert(kit_refcount(farray) == 1);
        kit_resettable(t);
        assert(kit_refcount(farray) == 0);
        kit_sweep(NULL);
        assert(kit_type(float)->instances == 0);
    }

    /* test ref array */ {
        float **refarray = kit_newrefs(float, 2);
        float *objs[2];
        assert(refarray[0] == NULL && refarray[1] == NULL);
        assert(!kit_isrefs(NULL));
        assert(kit_isrefs(refarray));
        objs[0] = kit_newobjects(float, 10);
        objs[1] = kit_newobjects(float, 10);
        assert(kit_refcount(objs[0]) == 0);
        assert(kit_refcount(objs[1]) == 0);
        kit_setobject(refarray[0], objs[0]);
        kit_setobject(refarray[1], objs[1]);
        assert(kit_refcount(objs[0]) == 1);
        assert(kit_refcount(objs[1]) == 1);
        kit_retain_all(refarray);
        assert(kit_refcount(objs[0]) == 2);
        assert(kit_refcount(objs[1]) == 2);
        kit_sweep(NULL);
        assert(kit_refcount(objs[0]) == 1);
        assert(kit_refcount(objs[1]) == 1);
        kit_release(objs[0]); kit_release(objs[1]);
        assert(kit_refcount(objs[0]) == 0);
        assert(kit_refcount(objs[1]) == 0);
        kit_sweep(NULL);
        assert(kit_type(float)->instances == 0);
    }

    /* test table */ {
        kit_Entry *e;
        size_t sym_count = KIT_TP(SYMBOL)->instances;
        kit_freetable(t);
        assert(*t == NULL);
        assert(kit_counttable(t) == 0);
        assert(kit_getfield(t, "foo") == NULL);
        kit_setfield(t, "foo", KIT_(bar));
        kit_setfield(t, "bar", KIT_(baz));
        e = kit_getfield(t, "foo");
        assert(e && e->key == KIT_(foo));
        assert(e && e->value == KIT_(bar));
        e = kit_getfield(t, "bar");
        assert(e && e->key == KIT_(bar));
        assert(e && e->value == KIT_(baz));
        assert(KIT_TP(SYMBOL)->instances == sym_count + 3);
        kit_sweep(NULL);
        assert(KIT_TP(SYMBOL)->instances == sym_count + 3);
        assert(kit_refcount(KIT_(foo)) == 1);
        assert(kit_refcount(KIT_(bar)) == 2);
        assert(kit_refcount(KIT_(baz)) == 1);
        kit_resettable(t);
        assert(*t != NULL);
        assert(kit_counttable(t) == 0);
        kit_sweep(NULL);
        assert(KIT_TP(SYMBOL)->instances == sym_count);
        assert(kit_refcount(KIT_(foo)) == 0);
        assert(kit_refcount(KIT_(bar)) == 0);
        assert(kit_refcount(KIT_(baz)) == 0);
        kit_sweep(NULL);
        assert(KIT_TP(SYMBOL)->instances == sym_count);
    }

    /* test pool */ {
    }

    return 0;
}
/* cc: flags+='-ggdb' */
