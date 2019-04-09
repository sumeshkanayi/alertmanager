{-
   Alertmanager API
   API of the Prometheus Alertmanager (https://github.com/sumeshkanayi/alertmanager)

   OpenAPI spec version: 0.0.1

   NOTE: This file is auto generated by the openapi-generator.
   https://github.com/openapitools/openapi-generator.git
   Do not edit this file manually.
-}


module Data.PeerStatus exposing (PeerStatus, decoder, encoder)

import Dict exposing (Dict)
import Json.Decode as Decode exposing (Decoder)
import Json.Decode.Pipeline exposing (optional, required)
import Json.Encode as Encode


type alias PeerStatus =
    { name : String
    , address : String
    }


decoder : Decoder PeerStatus
decoder =
    Decode.succeed PeerStatus
        |> required "name" Decode.string
        |> required "address" Decode.string


encoder : PeerStatus -> Encode.Value
encoder model =
    Encode.object
        [ ( "name", Encode.string model.name )
        , ( "address", Encode.string model.address )
        ]
