// Code generated by go-swagger; DO NOT EDIT.

// Copyright Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package alert

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/sumeshkanayi/alertmanager/api/v2/models"
)

// GetAlertsOKCode is the HTTP code returned for type GetAlertsOK
const GetAlertsOKCode int = 200

/*GetAlertsOK Get alerts response

swagger:response getAlertsOK
*/
type GetAlertsOK struct {

	/*
	  In: Body
	*/
	Payload models.GettableAlerts `json:"body,omitempty"`
}

// NewGetAlertsOK creates GetAlertsOK with default headers values
func NewGetAlertsOK() *GetAlertsOK {

	return &GetAlertsOK{}
}

// WithPayload adds the payload to the get alerts o k response
func (o *GetAlertsOK) WithPayload(payload models.GettableAlerts) *GetAlertsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get alerts o k response
func (o *GetAlertsOK) SetPayload(payload models.GettableAlerts) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetAlertsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if payload == nil {
		payload = make(models.GettableAlerts, 0, 50)
	}

	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}

// GetAlertsBadRequestCode is the HTTP code returned for type GetAlertsBadRequest
const GetAlertsBadRequestCode int = 400

/*GetAlertsBadRequest Bad request

swagger:response getAlertsBadRequest
*/
type GetAlertsBadRequest struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewGetAlertsBadRequest creates GetAlertsBadRequest with default headers values
func NewGetAlertsBadRequest() *GetAlertsBadRequest {

	return &GetAlertsBadRequest{}
}

// WithPayload adds the payload to the get alerts bad request response
func (o *GetAlertsBadRequest) WithPayload(payload string) *GetAlertsBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get alerts bad request response
func (o *GetAlertsBadRequest) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetAlertsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}

// GetAlertsInternalServerErrorCode is the HTTP code returned for type GetAlertsInternalServerError
const GetAlertsInternalServerErrorCode int = 500

/*GetAlertsInternalServerError Internal server error

swagger:response getAlertsInternalServerError
*/
type GetAlertsInternalServerError struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewGetAlertsInternalServerError creates GetAlertsInternalServerError with default headers values
func NewGetAlertsInternalServerError() *GetAlertsInternalServerError {

	return &GetAlertsInternalServerError{}
}

// WithPayload adds the payload to the get alerts internal server error response
func (o *GetAlertsInternalServerError) WithPayload(payload string) *GetAlertsInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get alerts internal server error response
func (o *GetAlertsInternalServerError) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetAlertsInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}
