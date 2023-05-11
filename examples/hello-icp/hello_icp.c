/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
/*******************************************************************************
* Running Hello world example
1. Deploy local Hello world canister
    1.1 In a separate directory create new hello world canister:
        > dfx new --type=rust rust_hello
    1.2 Change to your project directory:
        > cd rust_hello
    1.3 Start the local execution environment:
        > dfx start --background
    1.4 Register, build, and deploy the canister:
        > dfx deploy

2. Use IC-C agent to interact with local canister
    2.1 Inside IC-C folder configure Project and generate makefile:
        > cmake .
    2.2Compile and link project:
        > cmake --build .
    2.3 Run hello_world example:
        > ./hello_icp
The example sends the text "World" to the available canister service "greet",
the response is represented inside the () :
    Hello ICP! 
    ("Hello, World!")

DISCLAIMER: On Milestone 1 the team was focused on studying and understanding
the full scope of ICP network and also achieving a functional hello world 
example to test the acquired knowledge and prove the concept and usability of a
C wrapper for the rust agent.

For Milestone 2 the team will iterate over library code and structure, to improve
library usability. Namely, code consistency, memory management improvement and
removing the need for global variables.
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bindings.h"
#include "helper.h"
#include "agent.h"

#define CHECK_ERROR(e)              \
        if (e.len > 0) {            \
            printf("%s\n", e.ptr);   \
            return ERR;              \
        }                           \

Error error;
Identity id;

// Function pointers used to get the return from rust lib
static void error_cb(const uint8_t *p, int len) {
    error.ptr = malloc(len);
    error.len = len;
    memcpy((void *) error.ptr, p, len);
}

int main(void) {

    printf("Hello ICP! \n");

    // Canister info from hello world deploy example
    const char *id_text = "rrkah-fqaaa-aaaaa-aaaaq-cai";
    const char *did_file = "./examples/hello-icp/rust_hello_backend.did";
    const char *url = "http://127.0.0.1:4943";
    const char *method = "greet";
    const char *method_args = "(\"World\")";
    const char *method_args1 = "(\"Zondax\")";

    // Get did file content
    long file_size = get_did_file_size(did_file);
    char *did_content = malloc(file_size);
    get_did_file_content(did_file, file_size, did_content);

    // Compute principal id from text
    PrincipalRet_u8 principal = principal_from_text(id_text,error_cb);
    CHECK_ERROR(error);

    //compute id
    id.ptr = identity_anonymous();
    id.type = Anonym;

    // Create Agent 1
    FFIAgent *agent_1 = agent_create(url, &id, &principal, did_content, error_cb);
    CHECK_ERROR(error);
    char *call_1 = agent_query_wrap(agent_1, method, method_args, error_cb);
    CHECK_ERROR(error);


    // Create Agent 2
    FFIAgent *agent_2 = agent_create(url, &id, &principal, did_content, error_cb);
    CHECK_ERROR(error);
    char *call_2 = agent_query_wrap(agent_2, method, method_args1,error_cb);
    CHECK_ERROR(error);

    //Translate idl result
    char* text_1 = idl_args_to_text(call_1);
    char* text_2 = idl_args_to_text(call_2);
    printf("%s\n", text_1);
    printf("%s\n", text_2);

    // Free Memory
    free(did_content);
    free((void *) error.ptr);
    principal_free(principal.ptr);
    //identity_free(id.ptr);
    //agent_free(agent_1);
    return 0;
}
