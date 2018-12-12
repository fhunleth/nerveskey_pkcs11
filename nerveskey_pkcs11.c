/*
 * Copyright (c) 2014-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "pkcs11.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define CRYTOKI_VERSION { 2, 40 }
#define NKCS11_VERSION_MAJOR 0
#define NKCS11_VERSION_MINOR 1
#define NKCS11_VERSION_PATCH 0

static CK_INFO library_info = {
    .cryptokiVersion = CRYTOKI_VERSION,
    .manufacturerID = "NervesKey",
    .flags = 0,
    .libraryDescription = "PKCS#11 PIV Library (SP-800-73)",
    .libraryVersion = {NKCS11_VERSION_MAJOR, (NKCS11_VERSION_MINOR * 10) + NKCS11_VERSION_PATCH}
};

static CK_SLOT_INFO slot_0_info = {
    .slotDescription = "NervesKey Slot 0",
    .manufacturerID = "NervesKey",
    .flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT,
    .hardwareVersion = {0, 10},
    .firmwareVersion = {0, 10}
};

static CK_TOKEN_INFO slot_0_token_info = {
    .label = "Label",
    .manufacturerID = "NervesKey",
    .model = "Model",
    .serialNumber = "FILLIN",
    .flags = CKF_WRITE_PROTECTED | CKF_TOKEN_INITIALIZED,
    .ulMaxSessionCount = 1,
    .ulSessionCount = 0,
    .ulMaxRwSessionCount = 0,
    .ulRwSessionCount = 0,
    .ulMaxPinLen = 0,
    .ulMinPinLen = 0,
    .ulTotalPublicMemory = 0, // ??
    .ulFreePublicMemory = 0,
    .ulTotalPrivateMemory = 100,
    .ulFreePrivateMemory = 0,
    .hardwareVersion = {0, 10},
    .firmwareVersion = {0, 10},
    .utcTime = ""
};

static CK_FUNCTION_LIST function_list;

struct nerves_key_session {
    CK_ULONG open_count;
    CK_ULONG find_index;
};

static struct nerves_key_session session;

// See https://www.cryptsoft.com/pkcs11doc/

// https://www.cryptsoft.com/pkcs11doc/v220/pkcs11__all_8h.html

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
    CK_VOID_PTR pInitArgs
)
{
    DIN;
    (void) pInitArgs;

    memset(&session, 0, sizeof(session));

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
    CK_VOID_PTR pReserved
)
{
    DIN;
    (void) pReserved;
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
    CK_INFO_PTR pInfo
)
{
    DIN;
    *pInfo = library_info;
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
    CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
    DIN;

    if(ppFunctionList == NULL_PTR) {
        DBG("GetFunctionList called with ppFunctionList = NULL");
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = &function_list;

    DOUT;
    return CKR_OK;
}

/* Slot and token management */

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
    CK_BBOOL tokenPresent,
    CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount
)
{
    (void) tokenPresent;

    DIN;

    if (pSlotList == NULL_PTR) {
        *pulCount = 1;
    } else {
        if (*pulCount < 1)
            return CKR_BUFFER_TOO_SMALL;
        *pulCount = 1;
        *pSlotList = 0; // Slot 0 is the only slot
    }

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
    CK_SLOT_ID slotID,
    CK_SLOT_INFO_PTR pInfo
)
{
    DIN;

    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;

    *pInfo = slot_0_info;

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
    CK_SLOT_ID slotID,
    CK_TOKEN_INFO_PTR pInfo
)
{
    DIN;

    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;
    *pInfo = slot_0_token_info;

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
    CK_FLAGS flags,
    CK_SLOT_ID_PTR pSlot,
    CK_VOID_PTR pReserved
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount
)
{
    DIN;

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo
)
{
    DIN;


    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
    CK_SLOT_ID slotID,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel
)
{
    DIN;
    DBG("Token initialization unsupported");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
    CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen
)
{
    DIN;
    DBG("PIN initialization unsupported");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
    CK_SESSION_HANDLE hSession,
    CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen,
    CK_UTF8CHAR_PTR pNewPin,
    CK_ULONG ulNewLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;

}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    CK_VOID_PTR pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession
)
{
    DIN;
    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;
    if (phSession == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    if ((flags & CKF_SERIAL_SESSION) == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    if ((flags & CKF_RW_SESSION))
        return CKR_TOKEN_WRITE_PROTECTED;

    // Unused
    (void) pApplication;
    (void) Notify;

    phSession = 0;
    session.open_count++;

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
    CK_SESSION_HANDLE hSession
)
{
    DIN;

    if (hSession != 0 || session.open_count == 0)
        return CKR_SLOT_ID_INVALID;

    session.open_count--;

    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
    CK_SLOT_ID slotID
)
{
    DIN;
    if (slotID != 0)
        return CKR_SLOT_ID_INVALID;

    session.open_count = 0;
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
    CK_SESSION_HANDLE hSession,
    CK_SESSION_INFO_PTR pInfo
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState,
    CK_ULONG_PTR pulOperationStateLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(
    CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
    CK_SESSION_HANDLE hSession
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phNewObject
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;

    if (pTemplate == NULL_PTR || ulCount == 0)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv_final = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV rv;

        switch (pTemplate[i].type) {
        case CKA_KEY_TYPE:
            // Type of key.
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >= sizeof(CK_ULONG)) {
                pTemplate[i].ulValueLen = sizeof(CK_ULONG);
                *((CK_ULONG *) pTemplate[i].pValue) = CKK_ECDSA;
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;

        case CKA_LABEL:
            // Description of the object (default empty).
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = 3;
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >= 3) {
                pTemplate[i].ulValueLen = 3;
                strcpy((char *) pTemplate[i].pValue, "0");
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;

        case CKA_ID:
            // Key identifier for public/private key pair (default empty).
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = 1;
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >= 1) {
                pTemplate[i].ulValueLen = 1;
                *((CK_BYTE *) pTemplate[i].pValue) = '0';
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;

        case CKA_EC_PARAMS:
            // DER-encoding of an ANSI X9.62 Parameters value.
        {
            static const CK_BYTE prime256v1[] = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = sizeof(prime256v1);
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >= sizeof(prime256v1)) {
                pTemplate[i].ulValueLen = sizeof(prime256v1);
                memcpy(pTemplate[i].pValue, prime256v1, sizeof(prime256v1));
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;
        }
        case CKA_EC_POINT:
            // DER-encoding of ANSI X9.62 ECPoint value ''Q''.
        {
            // TODO: REPLACE WITH PUBLIC KEY
            DBG("FIXME!!! CKA_EC_POINT is returning bogus data!!!")
            static const CK_BYTE publickey[] = "\x04\x5c\x49\x7f\x64\xb3\x5d\x07\x4d\xd6\x2c\x79\xf0\xfc\x9f\x7d\x57\xb6\xe8\x78\xd0\xaf\xc3\xdb\xb6\xfc\x73\x9c\x14\xe3\x10\xe8\x34\xf5\xd2\xa8\x2d\xad\xce\xac\xec\xda\x30\x83\xb0\x8f\x67\x49\xca\x5c\x32\x9e\xba\x38\x02\x92\xac\x22\x1b\x00\x10\xc0\x4c\x15\xab";
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = sizeof(publickey);
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >= sizeof(publickey)) {
                pTemplate[i].ulValueLen = sizeof(publickey);
                memcpy(pTemplate[i].pValue, publickey, sizeof(publickey));
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;
        }

        case CKA_ALWAYS_AUTHENTICATE:
            // 	If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt) with the key.
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >=  sizeof(CK_BBOOL)) {
                pTemplate[i].ulValueLen =  sizeof(CK_BBOOL);
                *((CK_BBOOL *) pTemplate[i].pValue) = CK_FALSE;
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;

        case CKA_SIGN:
            // 	CK_TRUE if key supports signatures where the signature is an appendix to the data.
            if (pTemplate[i].pValue == NULL_PTR) {
                pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
                rv = CKR_OK;
            } else if (pTemplate[i].ulValueLen >=  sizeof(CK_BBOOL)) {
                pTemplate[i].ulValueLen =  sizeof(CK_BBOOL);
                *((CK_BBOOL *) pTemplate[i].pValue) = CK_TRUE;
                rv = CKR_OK;
            } else {
                pTemplate[i].ulValueLen = (CK_ULONG) -1;
                rv = CKR_BUFFER_TOO_SMALL;
            }
            break;

        default:
            pTemplate[i].ulValueLen = (CK_ULONG) -1;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            break;
        }
        // TODO: this function has some complex cases for return vlaue. Make sure to check them.
        if (rv != CKR_OK) {
            DBG("Unable to get attribute 0x%lx of object %lu", pTemplate[i].type, hObject);
            rv_final = rv;
        }
    }

    DOUT;
    return rv_final;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;

    if (pTemplate == NULL_PTR || ulCount == 0)
        return CKR_ARGUMENTS_BAD;

    CK_RV rv_final = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV rv = CKR_ATTRIBUTE_TYPE_INVALID;

        // TODO: this function has some complex cases for return vlaue. Make sure to check them.
        if (rv != CKR_OK) {
            DBG("Unable to set attribute 0x%lx of object %lu", pTemplate[i].type, hObject);
            rv_final = rv;
        }
    }
    DOUT;
    return rv_final;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    DIN;

    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;

    session.find_index = 0;
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;

    if (ulMaxObjectCount > 0 && session.find_index == 0) {
        *phObject = 0;
        *pulObjectCount = 1;
        session.find_index++;
    } else {
        *pulObjectCount = 0;
    }
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
    CK_SESSION_HANDLE hSession
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;
    DOUT;
    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    DBG("Trying to sign some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey);

    CK_RV rv;
    switch (pMechanism->mechanism) {
    case CKM_ECDSA:
        rv = CKR_OK;
        break;

    default:
        rv = CKR_MECHANISM_INVALID;
        break;
    }

    DOUT;
    return rv;
}

static void dump_data(CK_BYTE_PTR pData,
                      CK_ULONG ulDataLen)
{
    for (CK_ULONG i = 0; i < ulDataLen; ) {
        fprintf(stderr, "%02x %02x %02x %02x\r\n", pData[0], pData[1], pData[2], pData[3]);
        i += 4;
        pData += 4;
    }
}
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    DIN;
    if (hSession != 0 || session.open_count == 0)
        return CKR_SESSION_HANDLE_INVALID;
    if (pData == NULL_PTR || pSignature == NULL_PTR || pulSignatureLen == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    // P256

    DBG("Load %lu bytes into TempKey", ulDataLen);
    dump_data(pData, ulDataLen);
    if (ulDataLen != 32)
        return CKR_ARGUMENTS_BAD;
    DBG("Call Sign with Mode<7>=1");

    memset(pData, 0xaa, 64);
    *pulSignatureLen = 64;

    DOUT;

    return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

/* Random number generation functions */

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSeed,
    CK_ULONG ulSeedLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
    CK_SESSION_HANDLE hSession
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
    CK_SESSION_HANDLE hSession
)
{
    DIN;
    DBG("TODO!!!");
    DOUT;
    return CKR_FUNCTION_FAILED;
}

static CK_FUNCTION_LIST function_list = {
    CRYTOKI_VERSION,
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};
