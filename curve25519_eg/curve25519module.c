/* tell python that PyArg_ParseTuple(t#) means Py_ssize_t, not int */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
	typedef int Py_ssize_t;
#endif

/* This is required for compatibility with Python 2. */
#if PY_MAJOR_VERSION >= 3
	#include <bytesobject.h> 
	#define y "y"
#else
	#define PyBytes_FromStringAndSize PyString_FromStringAndSize
	#define y "t"
#endif

#include "curve25519-donna.h"

static PyObject *
pycurve25519_makeelement(PyObject *self, PyObject *args)
{
    char *in1;
    char result[32];
    size_t i;
    Py_ssize_t in1len;
    if (!PyArg_ParseTuple(args, y"#:makelement", &in1, &in1len))
        return NULL;
    if (in1len != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    for (i = 0; i < 32; ++i) result[i] = in1[i];
    result[0] &= 248;
    result[31] &= 127;
    result[31] |= 64;
    return PyBytes_FromStringAndSize((char *)result, 32);
}

static PyObject *
pycurve25519_curve(PyObject *self, PyObject *args)
{
    const char *x, *Y;
    char result[32];
    Py_ssize_t xlen, Ylen;
    if (!PyArg_ParseTuple(args, y"#"y"#:curve",
                          &x, &xlen, &Y, &Ylen))
        return NULL;
    if (xlen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    if (Ylen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(result, x, Y);
    return PyBytes_FromStringAndSize((char *)result, 32);
}

static PyObject *
pycurve25519_mul(PyObject *self, PyObject *args)
{
    char *a, *b;
    char result[32];
    limb al[10], bl[10], work[10];
    Py_ssize_t alen, blen;
    if (!PyArg_ParseTuple(args, y"#"y"#:mul",
                          &a, &alen, &b, &blen))
        return NULL;
    if (alen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    if (blen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    fexpand(al, a);
    fexpand(bl, b);
    fmul(work, al, bl);
    fcontract(result, work);
    return PyBytes_FromStringAndSize((char *)result, 32);
}

static PyObject *
pycurve25519_recip(PyObject *self, PyObject *args)
{
    char *a;
    char result[32];
    limb al[10], work[10];
    Py_ssize_t alen;
    if (!PyArg_ParseTuple(args, y"#:recip", &a, &alen))
        return NULL;
    if (alen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    fexpand(al, a);
    crecip(work, al);
    fcontract(result, work);
    return PyBytes_FromStringAndSize((char *)result, 32);
}

static PyMethodDef
curve25519_functions[] = {
    {"make_element", pycurve25519_makeelement, METH_VARARGS, "data->point"},
    {"curve", pycurve25519_curve, METH_VARARGS, "element+point->point"},
    {"mul", pycurve25519_mul, METH_VARARGS, "element*element->element"},
    {"recip", pycurve25519_recip, METH_VARARGS, "element->element"},
    {NULL, NULL, 0, NULL},
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef
    curve25519_module = {
        PyModuleDef_HEAD_INIT,
        "_curve25519",
        NULL,
        NULL,
        curve25519_functions,
    };

    PyObject *
    PyInit__curve25519(void)
    {
        return PyModule_Create(&curve25519_module);
    }
#else
    PyMODINIT_FUNC
    init_curve25519(void)
    {
          (void)Py_InitModule("_curve25519", curve25519_functions);
    }
#endif
