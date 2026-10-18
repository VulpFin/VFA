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

static PyObject *py_lz_encode(PyObject *self, PyObject *args)
{
    Py_buffer in;
    int level = 6, rc;
    PyObject *res;
    size_t cap, out_len = 0;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*|i", &in, &level)) return NULL;
    if (in.len > MAX_IN) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "input too large"); return NULL; }
    /* only output smaller than the input is useful (the writer stores the chunk otherwise): no 2x worst-case buffer */
    cap = (size_t)in.len + 4096;
    res = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)cap);
    if (!res) { PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = vulp_lz_encode((const uint8_t *)in.buf, (size_t)in.len, level, (uint8_t *)PyBytes_AS_STRING(res), cap, &out_len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc == VULP_E_SPACE) { Py_DECREF(res); Py_RETURN_NONE; }          /* does not fit: LZ does not pay off */
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    if (_PyBytes_Resize(&res, (Py_ssize_t)out_len) < 0) return NULL;
    return res;
}

static PyObject *py_lz_decode(PyObject *self, PyObject *args)
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
    rc = vulp_lz_decode((const uint8_t *)in.buf, (size_t)in.len, (uint8_t *)PyBytes_AS_STRING(res), (size_t)n);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    return res;
}

static PyObject *py_cm_encode(PyObject *self, PyObject *args)
{
    Py_buffer in;
    int tbits = 22, rc;
    PyObject *res;
    size_t cap, out_len = 0;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*|i", &in, &tbits)) return NULL;
    if (in.len > MAX_IN) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "input too large"); return NULL; }
    cap = (size_t)in.len + 4096;                     /* only output smaller than the input is useful */
    res = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)cap);
    if (!res) { PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = vulp_cm_encode((const uint8_t *)in.buf, (size_t)in.len, tbits, (uint8_t *)PyBytes_AS_STRING(res), cap, &out_len);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc == VULP_E_SPACE) { Py_DECREF(res); Py_RETURN_NONE; }
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    if (_PyBytes_Resize(&res, (Py_ssize_t)out_len) < 0) return NULL;
    return res;
}

static PyObject *py_cm_decode(PyObject *self, PyObject *args)
{
    Py_buffer in;
    Py_ssize_t n;
    int tbits, rc;
    PyObject *res;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*ni", &in, &n, &tbits)) return NULL;
    if (n < 0 || n > MAX_IN) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "bad output size"); return NULL; }
    res = PyBytes_FromStringAndSize(NULL, n);
    if (!res) { PyBuffer_Release(&in); return NULL; }
    Py_BEGIN_ALLOW_THREADS
    rc = vulp_cm_decode((const uint8_t *)in.buf, (size_t)in.len, tbits, (uint8_t *)PyBytes_AS_STRING(res), (size_t)n);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    if (rc != VULP_OK) { Py_DECREF(res); return err(rc); }
    return res;
}

static PyObject *py_cdc(PyObject *self, PyObject *args)
{
    Py_buffer in;
    unsigned int min_size, avg_log, max_size;
    size_t maxc, nc, i;
    uint64_t *cuts;
    PyObject *res;
    (void)self;
    if (!PyArg_ParseTuple(args, "y*III", &in, &min_size, &avg_log, &max_size)) return NULL;
    if (min_size == 0 || max_size < min_size) { PyBuffer_Release(&in); PyErr_SetString(PyExc_ValueError, "bad sizes"); return NULL; }
    maxc = (size_t)in.len / min_size + 2;
    cuts = (uint64_t *)PyMem_Malloc(maxc * sizeof(uint64_t));
    if (!cuts) { PyBuffer_Release(&in); return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS
    nc = vulp_cdc((const uint8_t *)in.buf, (size_t)in.len, min_size, avg_log, max_size, cuts, maxc);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&in);
    res = PyList_New((Py_ssize_t)nc);
    if (res) for (i = 0; i < nc; i++) PyList_SET_ITEM(res, (Py_ssize_t)i, PyLong_FromUnsignedLongLong(cuts[i]));
    PyMem_Free(cuts);
    return res;
}

static PyMethodDef methods[] = {
    {"tans_encode", py_tans_encode, METH_VARARGS, "tans_encode(data) -> bytes"},
    {"tans_decode", py_tans_decode, METH_VARARGS, "tans_decode(payload, raw_size) -> bytes (ValueError if corrupt)"},
    {"filter_fwd", py_filter_fwd, METH_VARARGS, "filter_fwd(id, params, data) -> bytes"},
    {"filter_inv", py_filter_inv, METH_VARARGS, "filter_inv(id, params, data) -> bytes"},
    {"cost", py_cost, METH_VARARGS, "cost(data) -> estimated order-0 coded size in 1/65536 bits"},
    {"lz_encode", py_lz_encode, METH_VARARGS, "lz_encode(data, level=6) -> bytes, or None if it would not be smaller"},
    {"lz_decode", py_lz_decode, METH_VARARGS, "lz_decode(payload, raw_size) -> bytes (ValueError if corrupt)"},
    {"cm_encode", py_cm_encode, METH_VARARGS, "cm_encode(data, tbits=22) -> bytes, or None if it would not be smaller"},
    {"cm_decode", py_cm_decode, METH_VARARGS, "cm_decode(payload, raw_size, tbits) -> bytes (ValueError if corrupt)"},
    {"cdc", py_cdc, METH_VARARGS, "cdc(data, min_size, avg_log, max_size) -> list of segment end offsets"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mod = { PyModuleDef_HEAD_INIT, "_vulp", "VFA2 codec core (vulp.c)", -1, methods, NULL, NULL, NULL, NULL };

PyMODINIT_FUNC PyInit__vulp(void)
{
    PyObject *m = PyModule_Create(&mod);
    if (m) PyModule_AddIntConstant(m, "VERSION", VULP_VERSION);
    return m;
}
