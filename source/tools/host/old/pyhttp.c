/*
 * Module:  pyhttp.c
 * Author:  Toni Uhlig <matzeton@googlemail.com>
 * Purpose: Python loadable module for http codes/flags
 */

#include "helper.h" /* must be the first include if compiling a python module */

#include <stdio.h>
#include <stdlib.h>

#include "compat.h"
#include "http.h"
#include "xor_strings.h" /* DLLSECTION */


static const char pname[] = "pyhttp";


static PyObject* info(PyObject* self, PyObject* args)
{
    printf("%s: http codes/flags\n", pname);
    Py_RETURN_NONE;
}

#define PYDICT_SET_CMACRO(name, obj) PyDict_SetItemString( dict, name, obj );
#define PYDICT_SETI_CMACRO(mname) { PyObject* pyval = Py_BuildValue("I", mname); if (pyval) { PYDICT_SET_CMACRO( #mname, pyval ); Py_DECREF(pyval); } }
#define PYDICT_SETS_CMACRO(mname) { PyObject* pyval = Py_BuildValue("s", mname); if (pyval) { PYDICT_SET_CMACRO( #mname, pyval ); Py_DECREF(pyval); } }
static PyObject* __http_getCodes(PyObject* self, PyObject* args)
{
    PyObject* dict = PyDict_New();
    PYDICT_SETI_CMACRO(RC_INFO);
    PYDICT_SETI_CMACRO(RC_REGISTER);
    PYDICT_SETI_CMACRO(RC_PING);
    return dict;
}

static PyObject* __http_getCodeSiz(PyObject* self, PyObject* args)
{
    return Py_BuildValue("I", sizeof(rrcode));
}

static PyObject* __http_getFlags(PyObject* self, PyObject* args)
{
    PyObject* dict = PyDict_New();
    PYDICT_SETI_CMACRO(RF_AGAIN);
    PYDICT_SETI_CMACRO(RF_ERROR);
    PYDICT_SETI_CMACRO(RF_OK);

    return dict;
}

static PyObject* __http_getFlagSiz(PyObject* self, PyObject* args)
{
    return Py_BuildValue("I", sizeof(rflags));
}

static PyObject* __http_getConsts(PyObject* self, PyObject* args)
{
    PyObject* dict = PyDict_New();
    PYDICT_SETS_CMACRO(DLLSECTION);
    PYDICT_SETI_CMACRO(SID_LEN);
    PYDICT_SETI_CMACRO(SID_ZEROES0);
    PYDICT_SETI_CMACRO(SID_ZEROES1);
    PYDICT_SETI_CMACRO(MARKER_SIZ);
    PYDICT_SETI_CMACRO(RND_LEN);
    PYDICT_SETI_CMACRO(AESKEY_SIZ);

    return dict;
}

static PyObject* __http_parseResponse(PyObject* self, PyObject* args)
{
    PyObject* ctxRecvBuffer = NULL;
    PyObject* ctxStartMarker = NULL;
    Py_buffer recvBuffer = {0}, startMarker = {0};
    PyObject* rList = Py_BuildValue("[]");

    if (! PyArg_ParseTuple(args, "O|O:parseResponse", &ctxRecvBuffer, &ctxStartMarker) ||
            ! ctxRecvBuffer || ! ctxStartMarker) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");
        PyErr_Print();
        return NULL;
    }

    if (PyObject_GetBuffer(ctxRecvBuffer, &recvBuffer, PyBUF_SIMPLE) < 0 ||
            PyObject_GetBuffer(ctxStartMarker, &startMarker, PyBUF_SIMPLE) < 0) {
        PyErr_SetString(PyExc_TypeError, "Argument types are not buffer objects");
        PyErr_Print();
        goto finalize;
    }
    if (recvBuffer.len <= 0) {
        PyErr_Format(PyExc_RuntimeError, "Invalid buffer length: %u", (unsigned)recvBuffer.len);
        PyErr_Print();
        goto finalize;
    }
    if (startMarker.len != MARKER_SIZ) {
        PyErr_Format(PyExc_TypeError, "Marker size is not exactly %u bytes: %u bytes", MARKER_SIZ, (unsigned)startMarker.len);
        PyErr_Print();
        goto finalize;
    }

    off_t bufOff = 0;
    http_resp* hResp = NULL;
    while (parseResponse(recvBuffer.buf, recvBuffer.len, &hResp, &bufOff, startMarker.buf) == RSP_OK &&
            hResp) {
        PyObject* tuple = Py_BuildValue("(s#BHIs#)", hResp->startMarker, MARKER_SIZ,
            hResp->respFlags, hResp->respCode, hResp->pkgsiz, &hResp->pkgbuf[0], hResp->pkgsiz);
        PyList_Append(rList, tuple);
        Py_DECREF(tuple);
    }

finalize:
    if (recvBuffer.buf != NULL)
        PyBuffer_Release(&recvBuffer);
    if (startMarker.buf != NULL)
        PyBuffer_Release(&startMarker);
    return rList;
}

static PyObject* __http_addRequest(PyObject* self, PyObject* args)
{
    struct http_resp* hResp = NULL;
    PyObject* ctxBuf;
    PyObject* ctxResp;
    Py_buffer pkgBuf = {0}, httpResp = {0};
    PyObject* retBuf = NULL;

    if (! PyArg_ParseTuple(args, "O|O:addRequest", &ctxBuf, &ctxResp) ||
            ! ctxBuf || ! ctxResp) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");
        return NULL;
    }

    if (PyObject_GetBuffer(ctxBuf, &pkgBuf, PyBUF_SIMPLE) < 0 ||
            PyObject_GetBuffer(ctxResp, &httpResp, PyBUF_SIMPLE) < 0) {
        PyErr_SetString(PyExc_TypeError, "Argument types are not buffer objects");
        PyErr_Print();
        goto finalize;
    }

    hResp = (struct http_resp*)httpResp.buf;
    if (httpResp.len != sizeof(struct http_resp) + hResp->pkgsiz) {
        PyErr_Format(PyExc_RuntimeError, "Invalid http_resp size: %lu (required: %lu + %u)", httpResp.len, sizeof(struct http_resp), hResp->pkgsiz);
        PyErr_Print();
        goto finalize;
    }

    rrsize send_siz = pkgBuf.len;
    rrbuff send_buf = COMPAT(calloc)(send_siz, sizeof(*send_buf));
    if (! send_buf)
        goto finalize;
    COMPAT(memcpy)(send_buf, pkgBuf.buf, send_siz);
    if (addRequest(&send_buf, &send_siz, hResp) == RSP_OK)
        retBuf = PyByteArray_FromStringAndSize((const char*)send_buf, send_siz);
    COMPAT(free)(send_buf);
finalize:
    if (pkgBuf.buf != NULL)
        PyBuffer_Release(&pkgBuf);
    if (httpResp.buf != NULL)
        PyBuffer_Release(&httpResp);
    if (retBuf)
        return retBuf;
    else
        Py_RETURN_NONE;
}


/* define module methods */
static PyMethodDef pycryptMethods[] = {
    {"info",           info,                    METH_NOARGS,  "print module info"},
    {"getCodes",       __http_getCodes,         METH_NOARGS,  "get http request/response codes"},
    {"getCodeSiz",     __http_getCodeSiz,       METH_NOARGS,  "get code size"},
    {"getFlags",       __http_getFlags,         METH_NOARGS,  "get http response flags"},
    {"getFlagSiz",     __http_getFlagSiz,       METH_NOARGS,  "get flag size"},
    {"getConsts",      __http_getConsts,        METH_NOARGS,  "get const data/macros"},
    {"parseResponse",  __http_parseResponse,    METH_VARARGS, "buf,startMarker -> parse http request/response"},
    {"addRequest",     __http_addRequest,       METH_VARARGS, "buf,struct http_resp -> add a http request to an pkgbuffer"},
    {NULL, NULL, 0, NULL}
};

/* module initialization */
PyMODINIT_FUNC
initpyhttp(void)
{
    printf("ENABLED %s\n", pname);
    (void) Py_InitModule(pname, pycryptMethods);
}
