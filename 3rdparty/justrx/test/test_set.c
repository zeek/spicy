
DECLARE_SET(foo, int, int, SET_STD_EQUAL)

static void print_set(set_foo* f)
{
    printf("size %d |", set_foo_size(f));
    set_for_each(foo, f, i) printf("%d ", i);
    printf("\n");
}

int main(int argc, char** argv)
{
    set_foo* s = set_foo_create(0);
    print_set(s);
    printf("empty: %d (1)\n", set_foo_empty(s));
    set_foo_insert(s, 10);
    set_foo_insert(s, 20);
    set_foo_insert(s, 30);
    set_foo_insert(s, 40);
    set_foo_insert(s, 25);
    set_foo_insert(s, 5);
    set_foo_insert(s, 45);
    print_set(s);
    printf("empty: %d (0)\n", set_foo_empty(s));

    set_foo_insert(s, 45);
    set_foo_insert(s, 45);
    print_set(s);

    set_foo_remove(s, 25);
    set_foo_remove(s, 5);
    set_foo_remove(s, 45);
    print_set(s);
    printf("empty: %d (0)\n", set_foo_empty(s));

    set_foo* o = set_foo_create(0);
    set_foo_insert(o, 10);
    set_foo_insert(o, 20);
    set_foo_insert(o, 30);
    set_foo_insert(o, 40);

    printf("equal: %d (1)\n", set_foo_equal(s, s));
    printf("equal: %d (1)\n", set_foo_equal(s, o));
    set_foo_remove(o, 10);
    printf("equal: %d (0)\n", set_foo_equal(s, o));
    set_foo_insert(o, 1100);
    printf("equal: %d (0)\n", set_foo_equal(s, o));

    set_foo_remove(s, 10);
    set_foo_remove(s, 20);
    set_foo_remove(s, 30);
    set_foo_remove(s, 40);
    set_foo_remove(s, 25);
    set_foo_remove(s, 5);
    set_foo_remove(s, 45);
    print_set(s);
    printf("empty: %d (1)\n", set_foo_empty(s));
}
