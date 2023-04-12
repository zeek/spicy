# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

"""X
    The Spicy domain for Sphinx.
"""

import os.path
from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.util.nodes import make_refnode, logging
from sphinx.util.console import bold, purple, darkgreen, red, term_width_line
from sphinx.roles import XRefRole
from sphinx.locale import _
from sphinx.domains import Domain, ObjType
from sphinx.directives.code import CodeBlock, LiteralInclude
from sphinx.directives import ObjectDescription
from sphinx import version_info
from sphinx import addnodes
import sys
import subprocess


def setup(Sphinx):
    Sphinx.add_domain(SpicyDomain)


logger = logging.getLogger(__name__)

# Wrapper for creating a tuple for index nodes, staying backwards
# compatible to Sphinx < 1.4:


def make_index_tuple(indextype, indexentry, targetname, targetname2):
    if version_info >= (1, 4, 0, '', 0):
        return (indextype, indexentry, targetname, targetname2, None)
    else:
        return (indextype, indexentry, targetname, targetname2)


class SpicyGeneric(ObjectDescription):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['spicy']['objects']
            key = (self.objtype, name)
            if key in objects:
                self.env.warn(self.env.docname,
                              'duplicate description of %s %s, ' %
                              (self.objtype, name) +
                              'other instance in ' +
                              self.env.doc2path(objects[key]),
                              self.lineno)
            objects[key] = self.env.docname
        indextext = self.get_index_text(self.objtype, name)
        if indextext:
            self.indexnode['entries'].append(make_index_tuple('single', indextext,
                                                              targetname, targetname))

    def get_index_text(self, objectname, name):
        return _('%s (%s)') % (name, self.objtype)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig


class SpicyOperator(SpicyGeneric):
    def handle_signature(self, sig, signode):
        m = sig.split()
        name = m[0]
        result = m[1].replace("~", " ")
        args = m[2:] if len(m) > 1 else []
        op = ""
        postfix = ""

        for a in args:
            if a.startswith("t:"):
                op += a[2:].replace("~", " ")

            elif a.startswith("a:"):
                op += a[2:]

            elif a.startswith("op:"):
                op += a[3:]

            elif a.startswith("x:"):
                op += a[2:].replace("-", " ")

            elif a == "<sp>":
                op += " "

            elif a == "$commutative$":
                postfix += " (commutative)"

            else:
                op += a.replace("~", " ")

        signode += nodes.literal("", op)

        if result != "-":
            signode += nodes.inline("", " → ")
            signode += nodes.literal("", result)

        if postfix:
            signode += nodes.superscript("", postfix)

        return name


class X(nodes.FixedTextElement):
    pass


class SpicyMethod(SpicyGeneric):
    def handle_signature(self, sig, signode):
        m = sig.split()
        name = m[0]
        self = m[1]
        method = m[2]
        const = m[3]
        result = m[4].replace("~", " ")
        args = sig[sig.find("(") + 1:-1].replace("~", " ")

#        try:
#            (ns, id) = result.split("::")
#            rnode = addnodes.pending_xref("", refdomain='spicy', reftype='type', reftarget=result)
#            rnode += nodes.literal("", id, classes=['xref'])
#
#        except ValueError:
#            rnode = nodes.inline("", result)

        signode += nodes.literal("", "%s(%s)" % (method, args))

        if result != "-":
            signode += nodes.inline("", " → ")
            signode += nodes.literal("", result)

        if const == "const":
            signode += nodes.inline("", " ")
            signode += nodes.superscript("", "(const)")

        return name


class SpicyType(SpicyGeneric):
    def handle_signature(self, sig, signode):
        name = sig

        if sig.find("::") > 0:
            signode += nodes.literal("", name)

        return name


class SpicyFunction(SpicyGeneric):
    def handle_signature(self, sig, signode):
        name = sig

        if sig.find("::") > 0:
            signode += nodes.strong("", name)

        return name


class SpicyMethodXRefRole(XRefRole):
    def process_link(self, env, refnode, has_explicit_title, title, target):
        i = title.find("::")

        if i > 0:
            title = title[i+2:] + "()"

        return title, target


class SpicyDomain(Domain):
    """Spicy domain."""
    name = 'spicy'
    label = 'Spicy'

    object_types = {
        'operator':    ObjType(_('operator'), 'op'),
        'method':      ObjType(_('method'),   'method'),
        'type':        ObjType(_('type'),     'type'),
        'function':    ObjType(_('function'), 'function'),
    }

    directives = {
        'operator':      SpicyOperator,
        'method':        SpicyMethod,
        'type':          SpicyType,
        'function':      SpicyFunction,
    }

    roles = {
        'op':         XRefRole(),
        'method':     SpicyMethodXRefRole(),
        'type':       XRefRole(),
        'function':   XRefRole(),
    }

    initial_data = {
        'objects': {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname):
        for (typ, name), doc in list(self.data['objects'].items()):
            if doc == docname:
                del self.data['objects'][typ, name]

    def resolve_xref(self, env, fromdocname, builder, typ, target, node,
                     contnode):
        objects = self.data['objects']
        objtypes = self.objtypes_for_role(typ)
        for objtype in objtypes:
            if (objtype, target) in objects:
                return make_refnode(builder, fromdocname,
                                    objects[objtype, target],
                                    objtype + '-' + target,
                                    contnode, target + ' ' + objtype)

    def get_objects(self):
        for (typ, name), docname in self.data['objects'].items():
            yield name, name, typ, docname, typ + '-' + name, 1


class SpicyCode(CodeBlock):
    required_arguments = 0
    optional_arguments = 1

    option_spec = {
        'exec': directives.unchanged
    }

    def __init__(self, *args, **kwargs):
        if len(args[1]) > 0:
            file = "_" + args[1][0]
        else:
            file = None

        args = list(args)
        args[1] = self.arguments = ['spicy']
        args[2]['lines'] = "2-"
        super(CodeBlock, self).__init__(*args, **kwargs)
        if file:
            self.file = self.env.relfn2path(os.path.join("examples/", file))
            try:
                os.mkdir(os.path.dirname(self.file))
            except:
                pass
        else:
            self.file = None

    def error(self, msg):
        self.state.document.settings.env.note_reread()
        msg = red(msg)
        logger.error(msg)
        return [msg]

    def message(self, msg):
        logger.info(msg)

    def run(self):
        literal = CodeBlock.run(self)
        language = literal[0]['language']

        if not self.file:
            return literal

        text = str(literal[0][0])

        if os.path.exists(self.file[1]):
            in_ = open(self.file[1])
            in_.readline()  # Skip header
            old = str(in_.read())
        else:
            old = ""

        if text != old:
            self.message("updating %s" % darkgreen(self.file[0]))
            f = open(self.file[1], "w")
            f.write(
                "# Automatically generated; edit in Sphinx source code, not here.\n")
            f.write(text)
            f.close()

        ntext = ""
        include = 1
        for line in text.split("\n"):
            if "%hide-begin%" in line:
                include -= 1
                continue

            if "%hide-end%" in line:
                include += 1
                continue

            if include > 0:
                ntext += line + "\n"

        ntext = ntext.strip()
        literal[0] = nodes.literal_block(ntext, ntext)
        literal[0]['language'] = language

        return literal


class SpicyOutput(LiteralInclude):
    required_arguments = 1
    optional_arguments = 1

    option_spec = {
        'exec': directives.unchanged_required,
        'prefix': directives.unchanged,
        'show-as': directives.unchanged,
        'show-with': directives.unchanged,
        'expect-failure': bool
    }

    def __init__(self, *args, **kwargs):
        options = args[2]

        self.exec_ = options["exec"].strip()
        self.prefix = options.get("prefix", None)
        self.show_as = ""
        self.show_with = ""
        self.expect_failure = ("expect-failure" in options)

        if "show-with" in options:
            self.show_with = options["show-with"]
            options["show-as"] = self.exec_

        if "show-as" in options:
            self.show_as = options.get("show-as", None)
            if not "prefix" in options:
                self.prefix = None

        self.content_hash = ("# Automatically generated; do not edit. -- <HASH> %s/%s/%s" %
                             (self.exec_,  self.show_as, self.expect_failure))

        source_orig = args[1][0]
        file = "_" + source_orig
        index = ("_%s" % args[1][1] if len(args[1]) > 1 else "")
        output = "examples/%s.output%s" % (file, index)
        args = list(args)
        args[1] = [output]
        args[2]['lines'] = "2-"
        args[2]['language'] = "text"
        super(LiteralInclude, self).__init__(*args, **kwargs)

        source = self.env.relfn2path(os.path.join("examples/", file))[0]
        self.update(source_orig, source, source + ".output%s" % index, self.exec_)

    def run(self):
        literal = LiteralInclude.run(self)

        if self.prefix:
            prefix = nodes.Text(self.prefix, self.prefix)
            return [prefix, literal[0]]
        else:
            return literal

    def update(self, source_orig, source, destination, cmd):
        if os.path.exists(destination) and not "UPDATE_SPICY_CODE" in os.environ:
            destination_time = os.path.getmtime(destination)

            if os.path.exists(source):
                source_time = os.path.getmtime(source)
            elif not "UPDATE_SPICY_CODE" in os.environ:
                return

            if source_time <= destination_time:
                hash = open(destination).readline().strip()
                if hash == self.content_hash:
                    return

        # When running from CI, all recorded output should be up to date.
        # Abort if that's not the case.
        if "CI" in os.environ:
            self.error(
                "error during CI: {} is not up to date in repository".format(destination))
            return

        all_good = True
        first = True

        show_as = []
        if self.show_as:
            show_as = self.show_as.split(";")

        for one_cmd in cmd.split(";"):
            one_cmd = one_cmd.strip()

            one_cmd = one_cmd.replace("%INPUT", source)
            self.message("executing %s" % darkgreen(one_cmd))

            try:
                output = subprocess.check_output(
                    one_cmd, shell=True, stderr=subprocess.STDOUT)

                if not output:
                    output = b"\n"

                if self.expect_failure:
                    self.error(
                        "execution of '%s' expected to fail, but succeeded")
                    all_good = False

            except subprocess.CalledProcessError as e:
                output = e.output
                if not self.expect_failure:
                    self.error("execution failed: " + e.output.decode("utf8"))
                    all_good = False

            if all_good:
                out = None
                if first:
                    out = open(destination, "wb")
                    out.write(self.content_hash.encode())
                    out.write(b"\n")
                else:
                    out = open(destination, "ab")
                    out.write(b"\n")

                if show_as:
                    one_cmd = "# %s\n" % show_as[0].strip()
                    one_cmd = one_cmd.replace("%INPUT", self.show_with if self.show_with else source_orig)
                    output = output.replace(
                        source.encode(), self.show_with.encode())
                    out.write(one_cmd.encode())
                    show_as = show_as[1:]

                out.write(output)
                out.close()
                first = False

    def error(self, msg):
        self.state.document.settings.env.note_reread()
        msg = red(msg)
        logger.error(msg)
        return [msg]

    def message(self, msg):
        logger.info(msg)


directives.register_directive('spicy-code', SpicyCode)
directives.register_directive('spicy-output', SpicyOutput)
