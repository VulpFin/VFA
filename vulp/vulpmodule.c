/* Copyright (C) 2025 TG11  -  AGPL-3.0-or-later (see LICENSE)
 *
 * _vulp - thin CPython wrapper around vulp.c (the codec itself has no Python dependency).
 * Errors become ValueError with the vulp error text; vfa2.py turns them into VFAError.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "vulp.h"

#define MAX_IN ((Py_ssize_t)1 << 31)

static PyObject *err(int rc) { PyErr_SetString(PyExc_ValueError, vulp_strerror(rc)); return NULL; }

static PyObject *py_tans_encode(PyObject *self, PyObject *args)
{
    Py_buffer in;
    PyObject *res;
    size_t cap, out_len = 0;
    int rc;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*", &in)) return NULL;
    if (in.len > MAX_IN) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "input too large"); return NULL; }
    cap = vulp_tans_bound((size_t)in.len);
    res = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)cap);
    if (!res) { PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = vulp_tans_encode((const uint8_t *)in.buf, (size_t)in.len, (uint8_t *)PyBytes_AS_STRING(res), cap, &out_len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    if (_PyBytes_Resize(&res, (Py_ssize_t)out_len) < 0) return NULL;
    return res;
}

static PyObject *py_tans_decode(PyObject *self, PyObject *args)
{
    Py_buffer in;
    Py_ssize_t n;
    PyObject *res;
    int rc;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*n", &in, &n)) return NULL;
    if (n < 0 || n > MAX_IN) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "bad output size"); return NULL; }
    res = PyBytes_FromStringAndSize(NULL, n);
    if (!res) { PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = vulp_tans_decode((const uint8_t *)in.buf, (size_t)in.len, (uint8_t *)PyBytes_AS_STRING(res), (size_t)n);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    return res;
}

static PyObject *filter_common(PyObject *args, int inverse)
{
    int fid, rc;
    Py_buffer p, in;
    PyObject *res;
    if (!PyArg_ParseTuple(args, "iy*y*", &fid, &p, &in)) return NULL;
    res = PyBytes_FromStringAndSize(NULL, in.len);
    if (!res) { PyBuffer_Release(&p); PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = (inverse ? vulp_filter_inv : vulp_filter_fwd)(fid, (const uint8_t *)p.buf, (size_t)p.len,
                                                       (const uint8_t *)in.buf, (uint8_t *)PyBytes_AS_STRING(res), (size_t)in.len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&p); PyBuffer_Release(&in);
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    return res;
}

static PyObject *py_filter_fwd(PyObject *self, PyObject *args) { (void)self; return filter_common(args, 0); }
static PyObject *py_filter_inv(PyObject *self, PyObject *args) { (void)self; return filter_common(args, 1); }

static PyObject *py_cost(PyObject *self, PyObject *args)
{
    Py_buffer in;
    uint64_t c;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*", &in)) return NULL;
    Py_BEGIN_ALLOW_THREADS
    c = vulp_cost_order0((const uint8_t *)in.buf, (size_t)in.len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    return PyLong_FromUnsignedLongLong(c);
}

static PyMethodDef methods[] = {
    {"tans_encode", py_tans_encode, METH_VARARGS, "tans_encode(data) -> bytes"},
    {"tans_decode", py_tans_decode, METH_VARARGS, "tans_decode(payload, raw_size) -> bytes (ValueError if corrupt)"},
    {"filter_fwd", py_filter_fwd, METH_VARARGS, "filter_fwd(id, params, data) -> bytes"},
    {"filter_inv", py_filter_inv, METH_VARARGS, "filter_inv(id, params, data) -> bytes"},
    {"cost", py_cost, METH_VARARGS, "cost(data) -> estimated order-0 coded size in 1/65536 bits"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mod = { PyModuleDef_HEAD_INIT, "_vulp", "VFA2 codec core (vulp.c)", -1, methods, NULL, NULL, NULL, NULL };

PyMODINIT_FUNC PyInit__vulp(void)
{
    PyObject *m = PyModule_Create(&mod);
    if (m) PyModule_AddIntConstant(m, "VERSION", VULP_VERSION);
    return m;
}
