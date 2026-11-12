// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// Tests for `goto` and labels. There's no HILTI syntax for them, so the tests
// build their ASTs through the builder and then compile them with the driver.

#include <doctest/doctest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include <hilti/rt/init.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/cfg.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

using namespace hilti;

namespace {

using FunctionBuilder = ExtendedBuilderTemplate<Builder>;

// Callback adding a module's declarations and its initialization code.
using ModuleBuilder = std::function<void(Builder* b, Declarations* decls, FunctionBuilder* init)>;

auto* int64(Builder* b) { return b->qualifiedType(b->typeSignedInteger(64), Constness::Mutable); }
auto* string(Builder* b) { return b->qualifiedType(b->typeString(), Constness::Mutable); }

// Returns a function whose body `build_body` fills in.
Declaration* makeFunction(Builder* b,
                          const ID& id,
                          QualifiedType* result,
                          const declaration::Parameters& params,
                          const std::function<void(FunctionBuilder*)>& build_body) {
    auto* body = b->statementBlock();
    FunctionBuilder fb(b->context(), body);
    build_body(&fb);
    return b->function(id, result, params, body);
}

std::string readFile(const hilti::rt::filesystem::path& p) {
    std::ifstream in(p);
    std::stringstream s;
    s << in.rdbuf();
    return s.str();
}

hilti::rt::filesystem::path tmpPath(const std::string& ext) {
    static int counter = 0;
    return hilti::rt::filesystem::temp_directory_path() /
           util::fmt("hilti-goto-test-%d-%d%s", getpid(), ++counter, ext);
}

// Callbacks giving tests access to the AST during compilation.
struct Hooks {
    // Runs after each round of resolving; returns true if it changed the
    // AST, which then gets resolved again.
    std::function<bool(ASTContext*, ASTRoot*)> resolved;

    // Runs before optimization; returns a report for the test to check.
    std::function<std::string(ASTContext*, ASTRoot*)> inspect;
};

class TestDriver : public Driver {
public:
    TestDriver(Hooks hooks) : Driver("hilti-goto-test", util::currentExecutable()), _hooks(std::move(hooks)) {}

    std::string report;

protected:
    bool hookNewASTPostCompilation(const Plugin& /*plugin*/, ASTRoot* root) override {
        return _hooks.resolved && _hooks.resolved(context()->astContext(), root);
    }

    Result<Nothing> hookCompilationFinished(ASTRoot* root) override {
        if ( _hooks.inspect )
            report = _hooks.inspect(context()->astContext(), root);

        return Nothing();
    }

private:
    Hooks _hooks;
};

struct Compiled {
    bool ok = false;
    std::string hilti;  // final HILTI code if compiled to HILTI
    std::string errors; // compiler diagnostics
    std::string report; // output of `Hooks::inspect`
};

enum class Mode { HILTI, Execute };

Compiled compileInProcess(const ModuleBuilder& build, Mode mode, bool optimize, const Hooks& hooks) {
    hilti::init();

    std::stringstream log;
    auto output = tmpPath(".hlt");

    TestDriver driver(hooks);

    driver::Options dopts;
    dopts.logger = std::make_unique<Logger>(log, log);

    if ( mode == Mode::HILTI ) {
        dopts.output_hilti = true;
        dopts.output_path = output;
    }
    else {
        dopts.execute_code = true;
        dopts.include_linker = true;
    }

    driver.setDriverOptions(std::move(dopts));

    auto copts = driver.hiltiOptions();
    copts.global_optimizations = optimize;
    driver.setCompilerOptions(copts);

    Compiled result;

    auto finish = [&](bool ok) {
        result.ok = ok;
        result.errors = log.str();
        result.report = driver.report;
        if ( ok && mode == Mode::HILTI )
            result.hilti = readFile(output);

        hilti::rt::filesystem::remove(output);
        return result;
    };

    if ( ! driver.initialize() )
        return finish(false);

    auto* b = driver.builder();
    Declarations decls;
    auto* init = b->statementBlock();
    FunctionBuilder init_builder(b->context(), init);
    build(b, &decls, &init_builder);

    auto uid = declaration::module::UID(ID("Test"), ".hlt", ".hlt");
    auto* module = b->declarationModule(uid, {}, decls, {init});
    b->context()->addModule(module);

    if ( auto rc = driver.addInput(module->uid()); ! rc ) {
        log << rc.error();
        return finish(false);
    }

    if ( auto rc = driver.compile(); ! rc ) {
        log << rc.error();
        return finish(false);
    }

    if ( mode == Mode::Execute ) {
        // Run the module's code ourselves so that we see exceptions.
        try {
            hilti::rt::init();
        } catch ( const std::exception& e ) {
            log << e.what();
            return finish(false);
        }
    }

    return finish(true);
}

void writeString(std::ostream& out, const std::string& s) { out << s.size() << '\n' << s; }

std::string readString(std::istream& in) {
    size_t size = 0;
    in >> size;
    in.get();
    std::string s(size, '\0');
    in.read(s.data(), static_cast<std::streamsize>(size));
    return s;
}

// Builds a module and compiles it. With `Mode::HILTI` this returns the
// optimized HILTI code. With `Mode::Execute` it JITs the code and runs the
// module's initialization code, reporting any exception as an error.
//
// Operators are initialized once per process for the first AST context, so
// each compilation runs in a child process of its own.
Compiled compile(const ModuleBuilder& build, Mode mode, bool optimize = true, const Hooks& hooks = {}) {
    auto result_path = tmpPath(".result");

    auto pid = fork();
    REQUIRE(pid >= 0);

    if ( pid == 0 ) {
        auto result = compileInProcess(build, mode, optimize, hooks);
        std::ofstream out(result_path, std::ios::binary);
        out << result.ok << '\n';
        writeString(out, result.hilti);
        writeString(out, result.errors);
        writeString(out, result.report);
        out.close();
        _exit(0);
    }

    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);

    Compiled result;
    std::ifstream in(result_path, std::ios::binary);
    in >> result.ok;
    in.get();
    result.hilti = readString(in);
    result.errors = readString(in);
    result.report = readString(in);
    in.close();
    hilti::rt::filesystem::remove(result_path);
    return result;
}

// Returns the HILTI code of the function `id` from the printed module.
std::string functionCode(const std::string& hilti, const std::string& id) {
    auto start = hilti.find(util::fmt(" %s(", id));
    REQUIRE(start != std::string::npos);
    auto end = hilti.find("\n}\n", start);
    REQUIRE(end != std::string::npos);
    return hilti.substr(start, end - start);
}

////// Functions with gotos

// x = 1; if ( b ) goto L; x = 2; L: return x;
//
// `L` is reached with two different values of `x`.
Declaration* forwardJump(Builder* b, const ID& id = "forward") {
    return makeFunction(b, id, int64(b), {b->parameter("b", b->typeBool())}, [](auto* fb) {
        fb->addLocal("x", int64(fb), fb->integer(1));
        fb->addIf(fb->id("b"))->addGoto("L");
        fb->addAssign(fb->id("x"), fb->integer(2));
        fb->addLabel("L");
        fb->addReturn(fb->id("x"));
    });
}

// Sums 0..n-1 through a backward jump.
Declaration* backwardJump(Builder* b) {
    return makeFunction(b, "backward", int64(b), {b->parameter("n", b->typeSignedInteger(64))}, [](auto* fb) {
        fb->addLocal("i", int64(fb), fb->integer(0));
        fb->addLocal("s", int64(fb), fb->integer(0));
        fb->addLabel("Top");
        fb->addIf(fb->equal(fb->id("i"), fb->id("n")))->addGoto("Done");
        fb->addAssign(fb->id("s"), fb->sum(fb->id("s"), fb->id("i")));
        fb->addAssign(fb->id("i"), fb->sum(fb->id("i"), fb->integer(1)));
        fb->addGoto("Top");
        fb->addLabel("Done");
        fb->addReturn(fb->id("s"));
    });
}

// Leaves a `while` loop once `i` reaches `n`.
Declaration* outOfWhile(Builder* b) {
    return makeFunction(b, "out_of_while", int64(b), {b->parameter("n", b->typeSignedInteger(64))}, [](auto* fb) {
        fb->addLocal("i", int64(fb), fb->integer(0));
        auto body = fb->addWhile(fb->lower(fb->id("i"), fb->integer(100)));
        body->addAssign(fb->id("i"), fb->sum(fb->id("i"), fb->integer(1)));
        body->addIf(fb->equal(fb->id("i"), fb->id("n")))->addGoto("Out");
        fb->addAssign(fb->id("i"), fb->integer(1000));
        fb->addLabel("Out");
        fb->addReturn(fb->id("i"));
    });
}

// Case 1 jumps over the code following the `switch`.
Declaration* outOfSwitch(Builder* b) {
    return makeFunction(b, "out_of_switch", int64(b), {b->parameter("v", b->typeSignedInteger(64))}, [](auto* fb) {
        fb->addLocal("r", int64(fb), fb->integer(0));
        auto switch_ = fb->addSwitch(fb->id("v"));
        auto c1 = switch_.addCase(fb->integer(1));
        c1->addAssign(fb->id("r"), fb->integer(10));
        c1->addGoto("Out");
        switch_.addCase(fb->integer(2))->addAssign(fb->id("r"), fb->integer(20));
        switch_.addDefault()->addAssign(fb->id("r"), fb->integer(30));
        fb->addAssign(fb->id("r"), fb->sum(fb->id("r"), fb->integer(1)));
        fb->addLabel("Out");
        fb->addReturn(fb->id("r"));
    });
}

// Leaves a `try` block early; otherwise divides by `z`, which may throw.
Declaration* outOfTry(Builder* b) {
    return makeFunction(b,
                        "out_of_try",
                        int64(b),
                        {b->parameter("b", b->typeBool()), b->parameter("z", b->typeSignedInteger(64))},
                        [](auto* fb) {
                            fb->addLocal("r", int64(fb), fb->integer(0));
                            auto [try_, catches] = fb->addTry();
                            try_->addAssign(fb->id("r"), fb->integer(1));
                            try_->addIf(fb->id("b"))->addGoto("Out");
                            try_->addAssign(fb->id("r"), fb->division(fb->integer(100), fb->id("z")));
                            catches.addCatch()->addAssign(fb->id("r"), fb->integer(3));
                            fb->addAssign(fb->id("r"), fb->sum(fb->id("r"), fb->integer(10)));
                            fb->addLabel("Out");
                            fb->addReturn(fb->id("r"));
                        });
}

// The label is reachable only through the goto, since it follows a `return`.
Declaration* afterReturn(Builder* b) {
    return makeFunction(b, "after_return", int64(b), {b->parameter("b", b->typeBool())}, [](auto* fb) {
        fb->addLocal("x", int64(fb), fb->integer(1));
        fb->addIf(fb->id("b"))->addGoto("L");
        fb->addReturn(fb->integer(0));
        fb->addLabel("L");
        fb->addReturn(fb->id("x"));
    });
}

// Appends `s` to `r` n times through a backward jump. `s` is still live
// after its use since the goto may come back to it.
Declaration* repeat(Builder* b, bool loop) {
    return makeFunction(b,
                        loop ? "repeat" : "repeat_once",
                        string(b),
                        {b->parameter("p", b->typeString()), b->parameter("n", b->typeSignedInteger(64))},
                        [&](auto* fb) {
                            fb->addLocal("s", string(fb), fb->sum(fb->id("p"), fb->stringMutable("a")));
                            fb->addLocal("r", string(fb), fb->stringMutable(""));
                            fb->addLocal("i", int64(fb), fb->integer(0));
                            fb->addLabel("Top");
                            fb->addAssign(fb->id("r"), fb->sum(fb->id("r"), fb->id("s")));
                            fb->addAssign(fb->id("i"), fb->sum(fb->id("i"), fb->integer(1)));
                            if ( loop )
                                fb->addIf(fb->lower(fb->id("i"), fb->id("n")))->addGoto("Top");
                            fb->addReturn(fb->id("r"));
                        });
}

// Leaves a nested block whose local `v` was copied into `x`; the label is
// reachable only through the goto, so `x` must not be replaced by `v` there.
Declaration* outOfScope(Builder* b) {
    return makeFunction(b,
                        "out_of_scope",
                        int64(b),
                        {b->parameter("a", b->typeSignedInteger(64)),
                         b->parameter("c", b->typeBool()),
                         b->parameter("d", b->typeBool())},
                        [](auto* fb) {
                            fb->addLocal("x", int64(fb), fb->integer(0));
                            auto then = fb->addIf(fb->id("c"));
                            then->addLocal("v", int64(fb), fb->sum(fb->id("a"), fb->integer(1)));
                            then->addAssign(fb->id("x"), fb->id("v"));
                            then->addIf(fb->id("d"))->addGoto("L");
                            fb->addReturn(fb->integer(1));
                            fb->addLabel("L");
                            auto block = fb->addBlock();
                            block->addLocal("y", int64(fb), fb->id("x"));
                            block->addReturn(fb->id("y"));
                        });
}

// A goto jumps past a `switch` that has only a default case holding just a
// declaration.
Declaration* defaultOnlySwitch(Builder* b) {
    return makeFunction(b,
                        "default_only_switch",
                        int64(b),
                        {b->parameter("b", b->typeBool()), b->parameter("s", b->typeString())},
                        [](auto* fb) {
                            fb->addLocal("x", int64(fb), fb->integer(1));
                            fb->addIf(fb->id("b"))->addGoto("L");
                            fb->addSwitch(fb->id("s")).addDefault()->addLocal("t", int64(fb), fb->integer(5));
                            fb->addAssign(fb->id("x"), fb->integer(2));
                            fb->addLabel("L");
                            fb->addReturn(fb->id("x"));
                        });
}

// A goto jumps past a nested block holding just a declaration.
Declaration* nestedDeclaration(Builder* b) {
    return makeFunction(b, "nested_declaration", int64(b), {b->parameter("b", b->typeBool())}, [](auto* fb) {
        fb->addLocal("x", int64(fb), fb->integer(1));
        fb->addIf(fb->id("b"))->addGoto("L");
        fb->addBlock()->addLocal("t", int64(fb), fb->integer(5));
        fb->addAssign(fb->id("x"), fb->integer(2));
        fb->addLabel("L");
        fb->addReturn(fb->id("x"));
    });
}

void check(FunctionBuilder* init, Expression* cond, const std::string& what) { init->addAssert(cond, what); }

void executionModule(Builder* b, Declarations* decls, FunctionBuilder* init) {
    decls->push_back(forwardJump(b));
    decls->push_back(backwardJump(b));
    decls->push_back(outOfWhile(b));
    decls->push_back(outOfSwitch(b));
    decls->push_back(outOfTry(b));
    decls->push_back(afterReturn(b));
    decls->push_back(repeat(b, true));
    decls->push_back(nestedDeclaration(b));
    decls->push_back(outOfScope(b));
    decls->push_back(defaultOnlySwitch(b));

    auto t = [&]() { return b->bool_(true); };
    auto f = [&]() { return b->bool_(false); };
    auto i = [&](int x) { return b->integer(x); };

    check(init, b->equal(b->call("forward", {t()}), i(1)), "forward(True)");
    check(init, b->equal(b->call("forward", {f()}), i(2)), "forward(False)");
    check(init, b->equal(b->call("backward", {i(5)}), i(10)), "backward(5)");
    check(init, b->equal(b->call("backward", {i(0)}), i(0)), "backward(0)");
    check(init, b->equal(b->call("out_of_while", {i(3)}), i(3)), "out_of_while(3)");
    check(init, b->equal(b->call("out_of_while", {i(200)}), i(1000)), "out_of_while(200)");
    check(init, b->equal(b->call("out_of_switch", {i(1)}), i(10)), "out_of_switch(1)");
    check(init, b->equal(b->call("out_of_switch", {i(2)}), i(21)), "out_of_switch(2)");
    check(init, b->equal(b->call("out_of_switch", {i(7)}), i(31)), "out_of_switch(7)");
    check(init, b->equal(b->call("out_of_try", {t(), i(0)}), i(1)), "out_of_try(True, 0)");
    check(init, b->equal(b->call("out_of_try", {f(), i(0)}), i(13)), "out_of_try(False, 0)");
    check(init, b->equal(b->call("out_of_try", {f(), i(4)}), i(35)), "out_of_try(False, 4)");
    check(init, b->equal(b->call("after_return", {t()}), i(1)), "after_return(True)");
    check(init, b->equal(b->call("after_return", {f()}), i(0)), "after_return(False)");
    check(init,
          b->equal(b->call("repeat", {b->stringMutable("x"), i(3)}), b->stringMutable("xaxaxa")),
          "repeat(\"x\", 3)");
    check(init, b->equal(b->call("nested_declaration", {t()}), i(1)), "nested_declaration(True)");
    check(init, b->equal(b->call("nested_declaration", {f()}), i(2)), "nested_declaration(False)");

    check(init, b->equal(b->call("out_of_scope", {i(5), t(), t()}), i(6)), "out_of_scope(5, True, True)");
    check(init, b->equal(b->call("out_of_scope", {i(5), t(), f()}), i(1)), "out_of_scope(5, True, False)");
    check(init,
          b->equal(b->call("default_only_switch", {t(), b->stringMutable("s")}), i(1)),
          "default_only_switch(True)");
    check(init,
          b->equal(b->call("default_only_switch", {f(), b->stringMutable("s")}), i(2)),
          "default_only_switch(False)");

    // Fails on purpose, showing that all checks above ran.
    check(init, b->equal(b->call("forward", {t()}), i(0)), "all checks passed");
}

// Returns the error output when compiling a single function built by `body`.
std::string validationErrors(const std::function<void(FunctionBuilder*)>& body,
                             const std::function<void(Builder*, Declarations*, FunctionBuilder*)>& extra = {}) {
    auto result = compile(
        [&](Builder* b, Declarations* decls, FunctionBuilder* init) {
            decls->push_back(makeFunction(b, "f", b->qualifiedType(b->typeVoid(), Constness::Const), {}, body));

            if ( extra )
                extra(b, decls, init);
        },
        Mode::HILTI);

    CHECK_FALSE(result.ok);
    return result.errors;
}

bool contains(const std::string& s, const std::string& x) { return s.find(x) != std::string::npos; }

Function* findFunction(Node* root, const ID& id) {
    for ( auto* n : visitor::range(visitor::PreOrder(), root, {}) ) {
        if ( auto* f = n->tryAs<Function>(); f && f->id() == id )
            return f;
    }

    return nullptr;
}

statement::Goto* findGoto(Node* root) {
    for ( auto* n : visitor::range(visitor::PreOrder(), root, {}) ) {
        if ( auto* g = n->tryAs<statement::Goto>() )
            return g;
    }

    return nullptr;
}

} // namespace

TEST_SUITE_BEGIN("Goto");

TEST_CASE("execution") {
    for ( auto optimize : {true, false} ) {
        CAPTURE(optimize);
        auto result = compile(executionModule, Mode::Execute, optimize);
        CAPTURE(result.errors);
        REQUIRE_FALSE(result.ok);
        CHECK(contains(result.errors, "all checks passed"));
    }
}

TEST_CASE("exceptions before an unconditional goto or return keep their catches") {
    for ( bool jump : {true, false} ) {
        for ( bool optimize : {true, false} ) {
            CAPTURE(jump);
            CAPTURE(optimize);
            auto result = compile(
                [&](Builder* b, Declarations* decls, FunctionBuilder* init) {
                    decls->push_back(
                        makeFunction(b,
                                     "divide",
                                     int64(b),
                                     {b->parameter("z", b->typeSignedInteger(64))},
                                     [](auto* fb) { fb->addReturn(fb->division(fb->integer(100), fb->id("z"))); }));
                    decls->push_back(
                        makeFunction(b,
                                     "throwing",
                                     int64(b),
                                     {b->parameter("z", b->typeSignedInteger(64))},
                                     [&](auto* fb) {
                                         fb->addLocal("r", int64(fb), fb->integer(7));
                                         auto [body, catches] = fb->addTry();
                                         body->addAssign(body->id("r"), body->call("divide", {body->id("z")}));
                                         if ( jump )
                                             body->addGoto("Done");
                                         else
                                             body->addReturn(body->id("r"));
                                         auto caught = catches.addCatch();
                                         caught->addAssert(caught->equal(caught->id("r"), caught->integer(7)),
                                                           "throwing assignment changed its target");
                                         caught->addAssert(caught->bool_(false), "catch preserved");
                                         if ( jump )
                                             fb->addLabel("Done");
                                         fb->addReturn(fb->id("r"));
                                     }));
                    init->addExpression(init->call("throwing", {init->integer(0)}));
                },
                Mode::Execute,
                optimize);
            CAPTURE(result.errors);
            CHECK_FALSE(result.ok);
            CHECK(contains(result.errors, "catch preserved"));
        }
    }
}

TEST_CASE("printer") {
    auto result = compile([](Builder* b, Declarations* decls, FunctionBuilder*) { decls->push_back(backwardJump(b)); },
                          Mode::HILTI,
                          false);
    CAPTURE(result.errors);
    REQUIRE(result.ok);

    auto code = functionCode(result.hilti, "backward");
    CHECK(contains(code, "\n    Top:\n"));
    CHECK(contains(code, "goto Done;"));
    CHECK(contains(code, "goto Top;"));
}

TEST_CASE("CFG edges") {
    // Describes the CFG around the goto in `forward()`.
    auto inspect = [](ASTContext* ctx, ASTRoot* root) -> std::string {
        auto* fn = findFunction(root, "forward");
        auto* label = statement::label::find(*fn->body(), "L");
        auto* goto_ = findGoto(fn->body());

        Declaration* x = nullptr;
        for ( auto* n : visitor::range(visitor::PreOrder(), fn->body(), {}) ) {
            if ( auto* d = n->tryAs<declaration::LocalVariable>(); d && d->id() == ID("x") )
                x = d;
        }

        if ( ! (label && goto_ && x) )
            return "missing nodes";

        std::stringstream report;
        report << "linked: " << (goto_->linkedLabel() == label) << '\n';

        auto cfg = detail::CFG(ctx, fn->body());
        const auto& graph = cfg.graph();

        // The goto sits inside an `if`, so it leaves that scope on its way.
        const auto& succ = graph.neighborsDownstream(goto_->identity());
        report << "goto successors: " << succ.size() << '\n';

        if ( succ.size() == 1 ) {
            const auto* end = graph.getNode(succ.front());
            report << "through scope end: " << (*end)->isA<detail::cfg::End>() << '\n';

            const auto& next = graph.neighborsDownstream(succ.front());
            report << "jumps to label: " << (next.size() == 1 && next.front() == label->identity()) << '\n';
        }

        // The label sees `x` from both its declaration and `x = 2`.
        const auto* node = graph.getNode(label->identity());
        const auto& in = cfg.dataflow().at(*node).in;
        report << "definitions of x reaching label: " << (in.contains(x) ? in.at(x).size() : 0) << '\n';
        return report.str();
    };

    auto result = compile(
        [](Builder* b, Declarations* decls, FunctionBuilder* init) {
            decls->push_back(forwardJump(b));
            init->addExpression(b->call("forward", {b->bool_(true)}));
        },
        Mode::HILTI,
        true,
        {.inspect = inspect});
    CAPTURE(result.errors);
    CHECK(result.ok);
    CHECK_EQ(result.report,
             "linked: 1\n"
             "goto successors: 1\n"
             "through scope end: 1\n"
             "jumps to label: 1\n"
             "definitions of x reaching label: 2\n");
}

TEST_CASE("goto relinked after deep copy") {
    const Node* old_label = nullptr;

    Hooks hooks;

    // Replace the resolved body with a copy, whose goto still points to the
    // original label.
    hooks.resolved = [&](ASTContext* ctx, ASTRoot* root) {
        if ( old_label )
            return false;

        auto* fn = findFunction(root, "forward");
        old_label = statement::label::find(*fn->body(), "L");
        fn->setBody(ctx, node::deepcopy(ctx, fn->body(), true));
        return true;
    };

    hooks.inspect = [&](ASTContext*, ASTRoot* root) {
        auto* fn = findFunction(root, "forward");
        auto* label = statement::label::find(*fn->body(), "L");
        auto* goto_ = findGoto(fn->body());
        return util::fmt("copied: %d relinked: %d", label != old_label, goto_ && goto_->linkedLabel() == label);
    };

    auto result = compile(
        [](Builder* b, Declarations* decls, FunctionBuilder* init) {
            decls->push_back(forwardJump(b));
            init->addExpression(b->call("forward", {b->bool_(true)}));
        },
        Mode::HILTI,
        true,
        hooks);
    CAPTURE(result.errors);
    CHECK(result.ok);
    CHECK_EQ(result.report, "copied: 1 relinked: 1");
}

TEST_CASE("value propagation across goto") {
    auto result = compile(
        [](Builder* b, Declarations* decls, FunctionBuilder* init) {
            decls->push_back(forwardJump(b));
            init->addExpression(b->call("forward", {b->bool_(true)}));
            init->addExpression(b->call("forward", {b->bool_(false)}));
        },
        Mode::HILTI);
    CAPTURE(result.errors);
    REQUIRE(result.ok);

    auto code = functionCode(result.hilti, "forward");
    CAPTURE(code);
    CHECK(contains(code, "return x;"));
}

TEST_CASE("move of value live along goto edge") {
    auto result = compile(
        [](Builder* b, Declarations* decls, FunctionBuilder* init) {
            decls->push_back(repeat(b, true));
            decls->push_back(repeat(b, false));
            init->addExpression(b->call("repeat", {b->stringMutable("x"), b->integer(3)}));
            init->addExpression(b->call("repeat_once", {b->stringMutable("x"), b->integer(3)}));
        },
        Mode::HILTI);
    CAPTURE(result.errors);
    REQUIRE(result.ok);

    // Without the goto, the use of `s` is its last one.
    auto once = functionCode(result.hilti, "repeat_once");
    CAPTURE(once);
    CHECK(contains(once, "move(s)"));

    auto loop = functionCode(result.hilti, "repeat");
    CAPTURE(loop);
    CHECK_FALSE(contains(loop, "move(s)"));
}

TEST_CASE("validation") {
    SUBCASE("label not at top level") {
        auto errors = validationErrors([](auto* fb) { fb->addIf(fb->bool_(true))->addLabel("L"); });
        CHECK(contains(errors, "label must be at the top level of a function body"));
    }

    SUBCASE("label outside of function") {
        auto errors = validationErrors([](auto* fb) {},
                                       [](Builder*, Declarations*, FunctionBuilder* init) { init->addLabel("L"); });
        CHECK(contains(errors, "label must be at the top level of a function body"));
    }

    SUBCASE("duplicate label") {
        auto errors = validationErrors([](auto* fb) {
            fb->addLabel("L");
            fb->addLabel("L");
        });
        CHECK(contains(errors, "duplicate label 'L'"));
    }

    SUBCASE("unknown label") {
        auto errors = validationErrors([](auto* fb) {
            fb->addLabel("L");
            fb->addGoto("M");
        });
        CHECK(contains(errors, "unknown label 'M'"));
    }

    SUBCASE("label of another function") {
        auto errors = validationErrors([](auto* fb) { fb->addGoto("L"); },
                                       [](Builder* b, Declarations* decls, FunctionBuilder*) {
                                           decls->push_back(forwardJump(b, "g"));
                                       });
        CHECK(contains(errors, "unknown label 'L'"));
    }

    SUBCASE("goto outside of function") {
        auto errors = validationErrors([](auto* fb) {},
                                       [](Builder*, Declarations*, FunctionBuilder* init) { init->addGoto("L"); });
        CHECK(contains(errors, "'goto' outside of function"));
    }

    SUBCASE("local after label") {
        auto errors = validationErrors([](auto* fb) {
            fb->addLabel("L");
            fb->addLocal("x", int64(fb), fb->integer(1));
        });
        CHECK(contains(errors, "top-level local cannot follow a label or goto"));
    }

    SUBCASE("local after goto") {
        auto errors = validationErrors([](auto* fb) {
            fb->addIf(fb->bool_(true))->addGoto("L");
            fb->addLocal("x", int64(fb), fb->integer(1));
            fb->addLabel("L");
        });
        CHECK(contains(errors, "top-level local cannot follow a label or goto"));
    }
}

TEST_SUITE_END();
