// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#define STANDARD_OPERATOR_1(ns_, kind_, result_, op_0, doc_)                                                           \
    class kind_ : public Operator {                                                                                    \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::kind_,                                                                                   \
                .op0 = {Const, op_0},                                                                                  \
                .result = {Const, result_},                                                                            \
                .ns = #ns_,                                                                                            \
                .doc = doc_,                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
        HILTI_OPERATOR(ns_::kind_)                                                                                     \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(kind_)


#define STANDARD_OPERATOR_2(ns_, kind_, result_, op_0, op_1, doc_)                                                     \
    class kind_ : public Operator {                                                                                    \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::kind_,                                                                                   \
                .op0 = {Const, op_0},                                                                                  \
                .op1 = {Const, op_1},                                                                                  \
                .result = {Const, result_},                                                                            \
                .ns = #ns_,                                                                                            \
                .doc = doc_,                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
        HILTI_OPERATOR(ns_::kind_)                                                                                     \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(kind_)

#define STANDARD_OPERATOR_3(ns_, kind_, result_, op_0, op_1, op_2, doc_)                                               \
    class kind_ : public Operator {                                                                                    \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::kind_,                                                                                   \
                .op0 = {Const, op_0},                                                                                  \
                .op1 = {Const, op_1},                                                                                  \
                .op2 = {Const, op_2},                                                                                  \
                .result = {Const, result_},                                                                            \
                .ns = #ns_,                                                                                            \
                .doc = doc_,                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
        HILTI_OPERATOR(ns_::kind_)                                                                                     \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(kind_)


#define STANDARD_OPERATOR_2x(ns_, cls, kind_, result_, op_0, op_1, doc_)                                               \
    class cls : public Operator {                                                                                      \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::kind_,                                                                                   \
                .op0 = {Const, op_0},                                                                                  \
                .op1 = {Const, op_1},                                                                                  \
                .result = {Const, result_},                                                                            \
                .ns = #ns_,                                                                                            \
                .doc = doc_,                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
        HILTI_OPERATOR(ns_::cls)                                                                                       \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(cls)

#define STANDARD_OPERATOR_2x_low_prio(ns_, cls, kind_, result_, op_0, op_1, doc_)                                      \
    LOW_PRIO();                                                                                                        \
    STANDARD_OPERATOR_2x(ns_, cls, kind_, result_, op_0, op_1, doc_)

#define STANDARD_OPERATOR_2x_lhs(ns_, cls, kind_, result_, op_0, op_1, doc_)                                           \
    LHS();                                                                                                             \
    STANDARD_OPERATOR_2x(ns_, cls, kind_, result_, op_0, op_1, doc_)

#define STANDARD_KEYWORD_CTOR(ns_, cls, kw, result_, op_, doc_)                                                        \
    class cls : public Operator {                                                                                      \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::Call,                                                                                    \
                .member = kw,                                                                                          \
                .param0 =                                                                                              \
                    {                                                                                                  \
                        .name = "xx",                                                                                  \
                        .type = {Const, op_},                                                                          \
                        .default_ = builder->expressionxx(),                                                           \
                        .optional = true,                                                                              \
                    },                                                                                                 \
                .result = {Const, result_},                                                                            \
                .ns = #ns_,                                                                                            \
                .doc = "xx",                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
        HILTI_OPERATOR(ns_::cls)                                                                                       \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(cls)

#define BEGIN_CTOR(ns_, cls)                                                                                           \
    class cls : public Operator {                                                                                      \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::Call,                                                                                    \
                .self = {Const, builder->typexx()},                                                                    \
                .param0 =                                                                                              \
                    {                                                                                                  \
                        .name = "xx",                                                                                  \
                        .type = {Const, builder->typexx},                                                              \
                        .default_ = builder->expressionxx(),                                                           \
                        .optional = true,                                                                              \
                    },                                                                                                 \
                .result_doc = "xx",                                                                                    \
                .ns = #ns_,                                                                                            \
                .doc = doc_,                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
                                                                                                                       \
        QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {         \
            return operands[0]->type();                                                                                \
        }                                                                                                              \
                                                                                                                       \
        HILTI_OPERATOR(ns_::cls)                                                                                       \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(cls)                                                                                 \
    @ @*;

#define END_CTOR @ @^;

#define __BEGIN_OPERATOR_CUSTOM(ns_, kind_, cls)                                                                       \
    class cls : public Operator {                                                                                      \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::kind_,                                                                                   \
                .op0 = {Const, xx},                                                                                    \
                .op1 = {Const, xx},                                                                                    \
                .result_doc = "xx",                                                                                    \
                .ns = #ns_,                                                                                            \
                .doc = "xx",                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
                                                                                                                       \
        QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {         \
            return xx;                                                                                                 \
        }                                                                                                              \
                                                                                                                       \
        std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {         \
            return {{op0(), xx op1()}};                                                                                \
        }                                                                                                              \
                                                                                                                       \
        void validate(expression::ResolvedOperator* n) const final {}                                                  \
                                                                                                                       \
        HILTI_OPERATOR(ns_::cls)                                                                                       \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(cls)                                                                                 \
    @ @*;


#define BEGIN_OPERATOR_CUSTOM(ns, op) __BEGIN_OPERATOR_CUSTOM(ns, op, op)
#define BEGIN_OPERATOR_CUSTOM_x(ns, cls, op) __BEGIN_OPERATOR_CUSTOM(ns, op, cls)

#define END_OPERATOR_CUSTOM @ @^;
#define END_OPERATOR_CUSTOM_x @ @^;

#define BEGIN_METHOD(ns_, cls)                                                                                         \
    class cls : public BuiltInMemberCall {                                                                             \
    public:                                                                                                            \
        Signature signature(Builder* builder) const final {                                                            \
            return {                                                                                                   \
                .kind = Kind::MemberCall,                                                                              \
                .self = {Const, builder->type##ns_()},                                                                 \
                .member = #cls,                                                                                        \
                .param0 =                                                                                              \
                    {                                                                                                  \
                        .name = "xx",                                                                                  \
                        .type = {Const, builder->typexx()},                                                            \
                        .default_ = builder->expressionxx(),                                                           \
                        .optional = true,                                                                              \
                    },                                                                                                 \
                .result = {Const, builder->typexx()},                                                                  \
                .ns = #ns_,                                                                                            \
                .doc = "xx",                                                                                           \
            };                                                                                                         \
        }                                                                                                              \
                                                                                                                       \
        HILTI_OPERATOR(ns_::cls);                                                                                      \
    };                                                                                                                 \
    HILTI_OPERATOR_IMPLEMENTATION(cls);                                                                                \
    @ @*;

#define END_METHOD @ @^;
