/*
 * Module:  pyloader.c
 * Author:  Toni Uhlig <matzeton@googlemail.com>
 * Purpose: Python loadable module for loader modifications
 */

#include "helper.h" /* must be the first include if compiling a python module */

#include <stdio.h>
#include <stdlib.h>

#include "loader.h"


static const char pname[] = "pyloader";
static const size_t ldr_strivkeylen = LOADER_STR_IVKEYLEN;
static const size_t ldr_ivkeylen = LOADER_IVKEYLEN;
static const char endmarker[] = { _LOADER_ENDMARKER };
static struct loader_x86_data loader86;


static PyObject* info(PyObject* self, PyObject* args)
{
    char* ldr_bufstr = bintostr((char*)&endmarker[0], sizeof(endmarker)/sizeof(endmarker[0]), 0, NULL);
    printf("%s: get miller loader data from python scripts\n"
             "\tLOADER_STR_IVKEYLEN: %lu\n"
             "\tLOADER_IVKEYLEN....: %lu\n"
             , pname, ldr_strivkeylen, ldr_ivkeylen);
    printf(  "\tENDMARKER..........: %s\n", ldr_bufstr);
    free(ldr_bufstr);
    Py_RETURN_NONE;
}

static PyObject* getLdrStrLen(PyObject* self, PyObject* args)
{
    return Py_BuildValue("(II)",
            sizeof(loader86.strVirtualAlloc)/sizeof(loader86.strVirtualAlloc[0]),
            sizeof(loader86.strIsBadReadPtr)/sizeof(loader86.strIsBadReadPtr[0]));
}

static PyObject* getLdrStrIvKeyLen(PyObject* self, PyObject* args)
{
    return Py_BuildValue("I", ldr_strivkeylen);
}

static PyObject* getLdrIvKeySiz(PyObject* self, PyObject* args)
{
    return Py_BuildValue("I", sizeof(loader86.key[0]));
}

static PyObject* getLdrIvKeyLen(PyObject* self, PyObject* args)
{
    return Py_BuildValue("I", ldr_ivkeylen);
}

static PyObject* getLdrStructSize(PyObject* self, PyObject* args)
{
    return Py_BuildValue("n", sizeof(loader86));
}

static PyObject* getLdrEndmarker(PyObject* self, PyObject* args)
{
    return Py_BuildValue("s#", &endmarker[0], sizeof(endmarker)/sizeof(endmarker[0]));
}

static PyObject* getLdrEndmarkerSize(PyObject* self, PyObject* args)
{
    return Py_BuildValue("n", sizeof(endmarker)/sizeof(endmarker[0]));
}

#define CALC_OFFSET(elem) ( (off_t)&(loader86.elem) - (off_t)&loader86 )
#define PYDICT_STRUCT_OFFSET(elem) { PyObject* pyval = Py_BuildValue("n", CALC_OFFSET(elem)); if (pyval) { PyDict_SetItemString( dict, #elem, pyval ); Py_DECREF(pyval); } }
static PyObject* getLdrStructOffsetDict(PyObject* self, PyObject* args)
{
    PyObject* dict = PyDict_New();
    PYDICT_STRUCT_OFFSET(strVirtualAlloc[0]);
    PYDICT_STRUCT_OFFSET(strIsBadReadPtr[0]);
    PYDICT_STRUCT_OFFSET(iv[0]);
    PYDICT_STRUCT_OFFSET(key[0]);
    PYDICT_STRUCT_OFFSET(flags);
    PYDICT_STRUCT_OFFSET(ptrToDLL);
    PYDICT_STRUCT_OFFSET(sizOfDLL);
    PYDICT_STRUCT_OFFSET(endMarker);
    PyDict_SetItemString(dict, "ldrStrLen", getLdrStrLen(self, args));
    PyDict_SetItemString(dict, "ldrStrIvKeyLen", getLdrStrIvKeyLen(self, args));
    PyDict_SetItemString(dict, "ldrIvKeySiz", getLdrIvKeySiz(self, args));
    PyDict_SetItemString(dict, "ldrIvKeyLen", getLdrIvKeyLen(self, args));
    PyDict_SetItemString(dict, "structSize", getLdrStructSize(self, args));
    PyDict_SetItemString(dict, "endMarkerSize", getLdrEndmarkerSize(self, args));
    return dict;
}

/* define module functions */
static PyMethodDef pyloaderMethods[] = {
    {"info",              info,                   METH_NOARGS, "module info"},
    {"getLdrStrLen",      getLdrStrLen,           METH_NOARGS, "get loader strings length"},
    {"getLdrStrIvKeyLen", getLdrStrIvKeyLen,      METH_NOARGS, "get loader string iv/key len"},
    {"getLdrIvKeySiz",    getLdrIvKeySiz,         METH_NOARGS, "get loader iv/key element size"},
    {"getLdrIvKeyLen",    getLdrIvKeyLen,         METH_NOARGS, "get loader iv/key len"},
    {"getStructSize",     getLdrStructSize,       METH_NOARGS, "get struct loader_x86_data size"},
    {"getEndmarker",      getLdrEndmarker,        METH_NOARGS, "get loader endmarker buffer"},
    {"getEndmarkerSize",  getLdrEndmarkerSize,    METH_NOARGS, "get loader endmarker bufsiz"},
    {"getStructOffset",   getLdrStructOffsetDict, METH_NOARGS, "get loader struct offset dict"},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/* module initialization */
PyMODINIT_FUNC
initpyloader(void)
{
    memset(&loader86, '\0', sizeof(loader86));
    printf("ENABLED %s\n", pname);
    (void) Py_InitModule(pname, pyloaderMethods);
}
