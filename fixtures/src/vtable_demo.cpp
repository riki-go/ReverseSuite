// C++ fixture for M6.3: virtual calls resolved through a vtable.
#include <stdio.h>

struct Base {
    virtual int value() { return 1; }
    virtual int other() { return 2; }
    virtual ~Base() {}
};

struct Derived : Base {
    int value() override { return 10; }
    int other() override { return 20; }
    int extra() { return 30; }
};

static int call_value(Base* b) { return b->value(); }
static int call_other(Base* b) { return b->other(); }

int main(int argc, char** argv) {
    Base base;
    Derived derived;
    Base* pick = (argc > 1) ? static_cast<Base*>(&derived) : &base;
    int total = call_value(pick) + call_other(pick) + derived.extra();
    printf("%d\n", total);
    return 0;
}
