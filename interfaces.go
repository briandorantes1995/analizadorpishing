package main

type URL struct {
	URL string `json:"url"`
}

type SecurityAssessment struct {
	Message   string   `json:"message"`
	RiskScore int      `json:"risk_score"`
	Reasons   []string `json:"reasons"`
}

type AuthVerdict struct {
	SPF   string `json:"spf"`
	DKIM  string `json:"dkim"`
	DMARC string `json:"dmarc"`
	IP    *IPInfo
}

type Summary struct {
	From              string `json:"from"`
	Subject           string `json:"subject"`
	Attachments_count int    `json:"attachments_count"`
	URLS_count        int    `json:"urls_count"`
}

type VirusTotalResult struct {
	Found   bool          `json:"found"`
	Message string        `json:"message,omitempty"`
	Stats   AnalysisStats `json:"stats,omitempty"`
}

type AnalysisStats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
}

type Attachment struct {
	Filename    string           `json:"filename"`
	ContentType string           `json:"content_type"`
	Hash        string           `json:"hash"`
	Results     VirusTotalResult `json:"results"`
}

type IPInfo struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	Query   string `json:"query"`
}

type Attachments []Attachment

type URLScanResponse struct {
	Message    string `json:"message"`
	Uuid       string `json:"uuid"`
	Visibility string `json:"visibility"`
	Url        string `json:"url"`
	Country    string `json:"country"`
	Result     string `json:"result"`
	Api        string `json:"api"`
}

type URLScanResponses []URLScanResponse

type Verdict struct {
	Score     int  `json:"score"`
	Malicious bool `json:"malicious"`
}

type URLVerdicts struct {
	Overall   Verdict `json:"overall"`
	Urlscan   Verdict `json:"urlscan"`
	Engines   Verdict `json:"engines"`
	Community Verdict `json:"community"`
}

type URLScanResult struct {
	Verdicts URLVerdicts `json:"verdicts"`
}

type URLScanResults []URLScanResult

type ApiResponse struct {
	Message        string         `json:"message"`
	RiskScore      int            `json:"risk_score"`
	Reasons        []string       `json:"reasons"`
	Summary        Summary        `json:"summary"`
	Authentication AuthVerdict    `json:"authentication"`
	Attachments    Attachments    `json:"attachments"`
	UrlResults     URLScanResults `json:"url_scan_results"`
}

type Html struct {
	Color      string `json:"color"`
	Icon       string `json:"icon"`
	Border     string `json:"border"`
	TitleColor string `json:"title_color"`
}
