package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/pam/recap/backend-go/internal/store"
)

// Attachment metadata only. The file bytes never reach this server; the client keeps them in
// private storage and sends a relative storageRef plus a content hash so another install can
// detect whether it already has the same file.

type attachmentCreate struct {
	TransactionID string         `json:"transactionId"`
	FileName      string         `json:"fileName"`
	MimeType      string         `json:"mimeType"`
	SizeBytes     int64          `json:"sizeBytes"`
	Sha256        string         `json:"sha256"`
	StorageRef    string         `json:"storageRef"`
	DeviceRef     string         `json:"deviceRef"`
	LocalFileID   string         `json:"localFileId"`
	Attributes    map[string]any `json:"attributes"`
}

type attachmentPatch struct {
	FileName   *string         `json:"fileName"`
	StorageRef *string         `json:"storageRef"`
	Attributes *map[string]any `json:"attributes"`
	Revision   int             `json:"revision"`
}

func attachmentJSON(attachment store.Attachment) map[string]any {
	attributes := attachment.Attributes
	if attributes == nil {
		attributes = map[string]any{}
	}
	return map[string]any{
		"id": attachment.ID, "transactionId": attachment.TransactionID,
		"fileName": attachment.FileName, "mimeType": attachment.Mime,
		"sizeBytes": attachment.SizeBytes, "sha256": attachment.Sha256,
		"storageRef": attachment.StorageRef, "deviceRef": nullString(attachment.DeviceRef),
		"localFileId": nullString(attachment.LocalFileID), "attributes": attributes,
		"revision": attachment.Revision, "createdAt": attachment.CreatedAt,
		"updatedAt": attachment.UpdatedAt,
	}
}

// retainAttachment applies the one-year window through the linked transaction. Attachments with no
// transaction (device-only metadata) carry no period identity and stay reachable; an attachment
// whose transaction is already gone is treated as expired metadata (404). Direct by-id reads and
// writes must not bypass the same window the list/create paths enforce.
func (s *Server) retainAttachment(w http.ResponseWriter, r *http.Request, ownerID string,
	attachment store.Attachment) bool {
	if attachment.TransactionID == "" {
		return true
	}
	eventAt, err := s.Store.TransactionEventAt(r.Context(), ownerID, attachment.TransactionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "Not found", correlationOf(r))
			return false
		}
		s.mapWriteError(w, r, err)
		return false
	}
	return s.retainNotExpired(w, r, eventAt)
}

func (s *Server) createAttachment(w http.ResponseWriter, r *http.Request) {
	var body attachmentCreate
	if !decodeJSON(w, r, &body) {
		return
	}
	info, _ := authFrom(r)
	if body.TransactionID != "" {
		transaction, err := s.Store.GetTransaction(r.Context(), info.OwnerID, body.TransactionID)
		if err != nil {
			s.mapWriteError(w, r, err)
			return
		}
		// Attachments are derivative metadata: never attach files to an expired transaction.
		if !s.retainNotExpired(w, r, transaction.EventAt) {
			return
		}
	}
	attachment, err := s.Store.CreateAttachment(r.Context(), info.OwnerID, store.AttachmentInput{
		TransactionID: body.TransactionID, FileName: body.FileName, Mime: body.MimeType,
		SizeBytes: body.SizeBytes, Sha256: body.Sha256, StorageRef: body.StorageRef,
		DeviceRef: body.DeviceRef, LocalFileID: body.LocalFileID, Attributes: body.Attributes,
	}, s.Now())
	if err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, attachmentJSON(attachment))
}

func (s *Server) listAttachments(w http.ResponseWriter, r *http.Request) {
	info, _ := authFrom(r)
	query := r.URL.Query()
	transactionID := query.Get("transactionId")
	limit, _ := strconv.Atoi(query.Get("limit"))
	page, err := s.Store.ListAttachments(r.Context(), info.OwnerID, transactionID,
		query.Get("mime"), query.Get("q"), limit, query.Get("cursor"))
	if err != nil {
		if errors.Is(err, store.ErrInvalidCursor) {
			writeError(w, http.StatusBadRequest, "invalid_cursor",
				"cursor was issued for a different query; restart from the first page", correlationOf(r))
			return
		}
		s.mapWriteError(w, r, err)
		return
	}
	// Cursor/scope validation runs first so a foreign cursor keeps returning 400 invalid_cursor; the
	// retention guard then applies the same one-year window to attachment listings of a transaction.
	if transactionID != "" {
		transaction, err := s.Store.GetTransaction(r.Context(), info.OwnerID, transactionID)
		if err != nil {
			s.mapWriteError(w, r, err)
			return
		}
		if !s.retainNotExpired(w, r, transaction.EventAt) {
			return
		}
	}
	// Without an explicit transaction filter the listing can span owners' whole history, so rows
	// whose transaction is outside the window are clamped out of the page. nextCursor is preserved
	// even when every row on this page was filtered so the client keeps advancing.
	expired := map[string]bool{}
	items := make([]map[string]any, 0, len(page.Items))
	for _, attachment := range page.Items {
		if transactionID == "" && attachment.TransactionID != "" {
			already, seen := expired[attachment.TransactionID]
			if !seen {
				eventAt, err := s.Store.TransactionEventAt(r.Context(), info.OwnerID, attachment.TransactionID)
				switch {
				case err == nil:
					already = s.retentionWindow().ValidateNotExpired(eventAt) != nil
				case errors.Is(err, store.ErrNotFound):
					already = true
				default:
					s.mapWriteError(w, r, err)
					return
				}
				expired[attachment.TransactionID] = already
			}
			if already {
				continue
			}
		}
		items = append(items, attachmentJSON(attachment))
	}
	response := map[string]any{"items": items}
	if page.NextCursor != "" {
		response["nextCursor"] = page.NextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) getAttachment(w http.ResponseWriter, r *http.Request) {
	info, _ := authFrom(r)
	attachment, err := s.Store.GetAttachment(r.Context(), info.OwnerID, r.PathValue("id"))
	if err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	if !s.retainAttachment(w, r, info.OwnerID, attachment) {
		return
	}
	writeJSON(w, http.StatusOK, attachmentJSON(attachment))
}

func (s *Server) updateAttachment(w http.ResponseWriter, r *http.Request) {
	var body attachmentPatch
	if !decodeJSON(w, r, &body) {
		return
	}
	info, _ := authFrom(r)
	current, err := s.Store.GetAttachment(r.Context(), info.OwnerID, r.PathValue("id"))
	if err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	if !s.retainAttachment(w, r, info.OwnerID, current) {
		return
	}
	attachment, err := s.Store.UpdateAttachment(r.Context(), info.OwnerID, r.PathValue("id"),
		store.AttachmentPatch{FileName: body.FileName, StorageRef: body.StorageRef,
			Attributes: body.Attributes, Revision: body.Revision}, s.Now())
	if err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, attachmentJSON(attachment))
}

func (s *Server) deleteAttachment(w http.ResponseWriter, r *http.Request) {
	expected := -1
	if r.Header.Get("If-Match") != "" {
		expected = revisionHeader(r)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("revision")); raw != "" {
		expected, _ = strconv.Atoi(raw)
	}
	info, _ := authFrom(r)
	current, err := s.Store.GetAttachment(r.Context(), info.OwnerID, r.PathValue("id"))
	if err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	if !s.retainAttachment(w, r, info.OwnerID, current) {
		return
	}
	if err := s.Store.DeleteAttachment(r.Context(), info.OwnerID, r.PathValue("id"),
		expected, s.Now()); err != nil {
		s.mapWriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
