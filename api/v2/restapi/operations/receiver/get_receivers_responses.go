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

package receiver

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/sumeshkanayi/alertmanager/api/v2/models"
)

// GetReceiversOKCode is the HTTP code returned for type GetReceiversOK
const GetReceiversOKCode int = 200

/*GetReceiversOK Get receivers response

swagger:response getReceiversOK
*/
type GetReceiversOK struct {

	/*
	  In: Body
	*/
	Payload []*models.Receiver `json:"body,omitempty"`
}

// NewGetReceiversOK creates GetReceiversOK with default headers values
func NewGetReceiversOK() *GetReceiversOK {

	return &GetReceiversOK{}
}

// WithPayload adds the payload to the get receivers o k response
func (o *GetReceiversOK) WithPayload(payload []*models.Receiver) *GetReceiversOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get receivers o k response
func (o *GetReceiversOK) SetPayload(payload []*models.Receiver) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetReceiversOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	payload := o.Payload
	if payload == nil {
		payload = make([]*models.Receiver, 0, 50)
	}

	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}

}
