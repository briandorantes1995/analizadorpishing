package main

type URL struct {
	URL string `json:"url"`
}

type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Hash        string `json:"hash"`
}

type Attachments []struct {
	Attachments []Attachment `json:"attachments"`
}
