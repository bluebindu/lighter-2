# Coding guidelines

For your code contributions, please follow the coding guidelines
outlined in this page.


## Style

These are the main rules to consider when writing code:

- follow [PEP8](https://www.python.org/dev/peps/pep-0008/) rules
- use English for all text
- use meaningful comments and object names
- use a context manager when opening a resource
  (files, gRPC channels, etc.)
- use the Python3's `.format()` method when formatting strings
- global variables should be uppercase
- all runtime configuration should be defined in the `settings`
  module
- to add logs use the `LOGGER` object
- add comments where code is not explicit enough
- private and dummy variable names should start with `_`


## Adding an implementation

In order to add support for a new implementation,
you will need to add two files: one for the translation module
and one for the related tests.
As an example, for an hypothetic implementation called
`FasterThanLighter`:

- `lighter/light_fasterthanlighter.py`
- `tests/test_light_fasterthanlighter.py`

Then you can implement just some of the rpc methods included in
`lighter.proto`.
For the one you will not implement, a default error will be shown,
signaling that the method is not supported.

Variable names for LN node requests and responses are built from a
shortened implementation name (2/3 chars) + `_req` / `_res`.
Example names from currently supported implementations are:
-  `cl_req` / `cl_res`
-  `ecl_req` / `ecl_res`
-  `ele_req` / `ele_res`
-  `lnd_req` / `lnd_res`

Use instead the full names `request` and `response` when
communicating with the client interface.

The following is an example of a basic gRPC method construction.
It uses the `utils.command()` function to call the LN node's CLI.

```python
def RpcMethodName(request, context):
    ftl_req = ['newaddress']
    if request.type is 0:
        ftl_req.append('p2wkh')
    elif request.type is 1:
        ftl_req.append('np2wkh')
    ftl_res = command(context, *ftl_req)
    if 'addr' in ftl_res:
        response.address = ftl_res['addr']
    _handle_error(context, ftl_res, always_abort=False)
    return response
```

Please note that not all implementations use the `command()` utility.
LND uses gRPC natively so Lighter takes advantage of that. Should a
new supported implementation use gRPC as well, the channel handling
code could be moved to the `utils` module.


## Errors handling

Errors returned by LN implementations may differ, just like
operations, but Lighter needs to keep the client error interface
agnostic with respect to the underlying implementation.

To do so, LN errors are mapped between a specific and a common error
dictionary <sup>1</sup>, then a dispatcher method in the `errors` module
builds the `grpc.RpcError` object (from the common dictionary) and returns it
to the client via grpc context. Setting an appropriate `StatusCode`
and message is also taken care of.

To add handling for an unmapped error you need to:
- identify a unique substring to match the implementation's error
- add an item to the `ERROR` dictionary using:
  - the identifed substring as key
  - the function to be called when handling the error <sup>2</sup>
  - the string representing the optional error function parameter
    <sup>3</sup>

An example error dictionary entry:
```python
ERRORS = {
    'string to be captured': {
        'fun': 'fun_to_call',
        'params': 'additional params to be passed'
    },
}
```

#### Notes

1. _see_ `utils.report_error()` _and the specific implementation of the_
   `_handle_error()` _method_
2. _see_ `errors.ERRORS`_'s keys for the list of available functions_
3. _supported if the erorr function's_ `msg` _contains_
   `%PARAM%`_, use_ `None` _otherwise_
4. _see the_ `errors` _module for details_
