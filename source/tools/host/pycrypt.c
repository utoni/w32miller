/*
 * Module:  pcrypt.c
 * Author:  Toni Uhlig <matzeton@googlemail.com>
 * Purpose: Python loadable module for xor/plain buffer (en|de)cryption
 */

#include "helper.h" /* must be the first include if compiling a python module */

#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "crypt.h"
#include "compat.h"


static const char pname[] = "pycrypt";
static bool aesInit = false;


static PyObject* info(PyObject* self, PyObject* args)
{
    printf("%s: (en|de)crypt xor/plain buffer\n", pname);
    Py_RETURN_NONE;
}

static int init(void)
{
    if (aesInit)
        aes_cleanup();
    aes_init();
    aesInit = true;
    return 0;
}

static int __checkAESKeySize(unsigned int ksiz)
{
    if (ksiz != KEY_128 && ksiz != KEY_192 && ksiz != KEY_256) {
        PyErr_Format(PyExc_TypeError, "Argument keysize must be either KEY_128(%d bytes), KEY_192(%d bytes) or KEY_256(%d bytes)", KEY_128, KEY_192, KEY_256);
        return 0;
    }
    return 1;
}

static int __checkCtxSize(void* buf, Py_ssize_t len)
{
    if (len < sizeof(aes_ctx_t)) {
        PyErr_Format(PyExc_TypeError, "Invalid AES Context struct size: %lu < %lu", len, sizeof(aes_ctx_t));
        return 0;
    }
    aes_ctx_t* ctx = (aes_ctx_t*)buf;
    uint32_t ks_size = 4*(ctx->rounds+1)*sizeof(uint32_t);
    if (len != sizeof(aes_ctx_t)+ks_size) {
        PyErr_Format(PyExc_TypeError, "Invalid AES Context rounds size: %lu < %lu", len, sizeof(aes_ctx_t)+ks_size);
        return 0;
    }
    return 1;
}

static PyObject* __aes_randomkey(PyObject* self, PyObject* args)
{
    unsigned int ksiz = 0;
    if (! PyArg_ParseTuple(args, "I:aesRandomKey", &ksiz)) {
        return NULL;
    }

    if (__checkAESKeySize(ksiz) == 0) {
        return NULL;
    }

    unsigned char key[ksiz];
    memset(&key[0], '\0', ksiz);
    aes_randomkey(&key[0], ksiz);
    return PyByteArray_FromStringAndSize((const char*)&key[0], ksiz);
}

static PyObject* __aes_allocCtx(PyObject* self, PyObject* args)
{
    PyObject* pyByteArray = NULL;
    Py_buffer pyByteBuffer;
    char* buf = NULL;
    ssize_t len;

    if (! PyArg_ParseTuple(args, "O:aesAllocCtx", &pyByteArray)) {
        PyErr_SetString(PyExc_TypeError, "Missing argument key as bytearray");
        return NULL;
    }
    if (PyObject_GetBuffer(pyByteArray, &pyByteBuffer, PyBUF_SIMPLE) < 0) {
        PyErr_SetString(PyExc_TypeError, "Argument is not a valid Bytebuffer");
        return NULL;
    }
    len = pyByteBuffer.len;
    if (__checkAESKeySize(len) == 0) {
        return NULL;
    }

    buf = pyByteBuffer.buf;
    aes_ctx_t* aes_ctx = aes_alloc_ctx((unsigned char*)buf, len);

    PyObject* ctxByteArray = NULL;
    if (aes_ctx) {
        ssize_t size = sizeof(aes_ctx_t)+4*(aes_ctx->rounds+1)*sizeof(uint32_t);
        ctxByteArray = PyByteArray_FromStringAndSize((const char*)aes_ctx, size);
    }
    aes_free_ctx(aes_ctx);
    PyBuffer_Release(&pyByteBuffer);
    return ctxByteArray;
}

static PyObject* __aes_crypt(PyObject* self, PyObject* args)
{
    Py_buffer plainBuffer;
    PyObject* plainByteArray = NULL;
    char* plain = NULL;
    Py_buffer ctxBuffer;
    PyObject* ctxByteArray = NULL;
    aes_ctx_t* aes_ctx = NULL;
    PyObject* boolDoEncrypt = NULL;
    bool doEncrypt = true;

    if (! PyArg_ParseTuple(args, "O|O|O:aesEncrypt", &ctxByteArray, &plainByteArray, &boolDoEncrypt) ||
            ! ctxByteArray || ! plainByteArray || ! boolDoEncrypt) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments (signature: AES_CTX[bytearray] BUFFER[bytearray] DO_ENCRYPT[bool]");
        return NULL;
    }
    if (PyObject_GetBuffer(ctxByteArray, &ctxBuffer, PyBUF_SIMPLE) < 0 ||
            PyObject_GetBuffer(plainByteArray, &plainBuffer, PyBUF_SIMPLE) < 0 ) {
        return NULL;
    }
    if (__checkCtxSize(ctxBuffer.buf, ctxBuffer.len) == 0) {
        PyErr_SetString(PyExc_TypeError, "Invalid aes context");
        return NULL;
    }

    aes_ctx = (aes_ctx_t*)ctxBuffer.buf;
    doEncrypt = PyObject_IsTrue(boolDoEncrypt);
    plain = plainBuffer.buf;

    uint32_t newsiz = 0;
    char* new = aes_crypt_s(aes_ctx, plain, plainBuffer.len, &newsiz, doEncrypt);
    PyObject* out = PyByteArray_FromStringAndSize((const char*)new, newsiz);
    COMPAT(free)(new);
    PyBuffer_Release(&plainBuffer);
    PyBuffer_Release(&ctxBuffer);
    return out;
}

static int __check_xor32key(unsigned int ksiz)
{
    return ksiz <= 128;
}

static uint32_t __xor32_random(void)
{
    return xor32_randomkey();
}

static PyObject* __xor32_randomkeyiv(PyObject* self, PyObject* args)
{
    unsigned int ksiz = 0;
    if (! PyArg_ParseTuple(args, "I:xorRandomKey", &ksiz) ||
            __check_xor32key(ksiz) == 0) {
        PyErr_SetString(PyExc_TypeError, "Invalid argument for keysize");
        return NULL;
    }

    uint32_t buf[ksiz];
    memset(&buf[0], '\0', ksiz*sizeof(buf[0]));
    for (unsigned int i = 0; i < ksiz; ++i) {
        buf[i] = __xor32_random();
    }
    return PyByteArray_FromStringAndSize((const char*)&buf[0], ksiz*sizeof(buf[0]));
}

static PyObject* __xor32n_pcbc_crypt_buf(PyObject* self, PyObject* args)
{
    PyObject* result = NULL;
    PyObject* byteBuf = NULL;
    PyObject* keyBuf = NULL;
    PyObject* ivBuf = NULL;
    Py_buffer pyByteBuf, pyKeyBuf, pyIvBuf;

    if (! PyArg_ParseTuple(args, "O|O|O:xorCrypt", &byteBuf, &keyBuf, &ivBuf) ||
            ! byteBuf) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments (signature: BUFFER[bytearray] XORKEY[bytearray] IV[bytearray]");
        return NULL;
    }
    if (PyObject_GetBuffer(byteBuf, &pyByteBuf, PyBUF_SIMPLE) < 0 ||
            PyObject_GetBuffer(keyBuf, &pyKeyBuf, PyBUF_SIMPLE) < 0 ||
            PyObject_GetBuffer(ivBuf, &pyIvBuf, PyBUF_SIMPLE) < 0) {
        PyErr_SetString(PyExc_TypeError, "One or more arguments could not be exported into a Buffer View");
        goto failed;
    }

    if (pyKeyBuf.len != pyIvBuf.len) {
        PyErr_SetString(PyExc_TypeError, "Key and Iv length are not equal");
        goto failed;
    }
    if (pyKeyBuf.len % 4 != 0) {
        PyErr_SetString(PyExc_TypeError, "Key and Iv length must be a multiple of 4 bytes");
        goto failed;
    }

    size_t outsiz = pyByteBuf.len + sizeof(uint32_t)*pyKeyBuf.len;
    uint32_t* outbuf = PyMem_Malloc(outsiz);
    memset(outbuf, '\0', outsiz);
    memcpy(outbuf, pyByteBuf.buf, pyByteBuf.len);
    size_t newsiz = xor32n_pcbc_crypt_buf(outbuf, pyByteBuf.len, pyIvBuf.buf, pyKeyBuf.buf, pyKeyBuf.len / 4);
    result = PyByteArray_FromStringAndSize((const char*)outbuf, newsiz);
    PyMem_Free(outbuf);

failed:
    PyBuffer_Release(&pyByteBuf);
    PyBuffer_Release(&pyKeyBuf);
    PyBuffer_Release(&pyIvBuf);
    return result;
}


/* define module methods */
static PyMethodDef pycryptMethods[] = {
    {"info",           info,                    METH_NOARGS,  "print module info"},
    {"aesRandomKey",   __aes_randomkey,         METH_VARARGS, "generate random aes key"},
    {"aesAllocCtx",    __aes_allocCtx,          METH_VARARGS, "allocate memory for a aes encryption/decryption context"},
    {"aesCrypt",       __aes_crypt,             METH_VARARGS, "(en|de)crypt a memory buffer"},
    {"xorRandomKeyIv", __xor32_randomkeyiv,     METH_VARARGS, "generate a random xor key/iv 32-bit sequence"},
    {"xorCrypt",       __xor32n_pcbc_crypt_buf, METH_VARARGS, "(en|de)crypt a memory buffer"},
    {NULL, NULL, 0, NULL}
};

/* module initialization */
PyMODINIT_FUNC
initpycrypt(void)
{
    srandom(time(NULL));

    if (init() != 0) {
        printf("%s: Error while initializing module\n", pname);
    } else {
        printf("ENABLED %s\n", pname);
        PyObject* m = Py_InitModule(pname, pycryptMethods);
        if (m) {
            if (PyModule_AddIntMacro(m, KEY_128) != 0 ||
                    PyModule_AddIntMacro(m, KEY_192) != 0 ||
                    PyModule_AddIntMacro(m, KEY_256) != 0) {
                printf("Failed to add some Macro's ..\n");
            }
        }
    }
}
