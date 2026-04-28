package analyzer

import (
	"sort"
	"strings"

	"quarant/analyzer/knowledge"
)

type userGuidanceTemplate struct {
	title     string
	message   string
	impact    string
	actionIDs []string
}

func EnrichUserGuidance(e *Event, catalog knowledge.UserActionCatalog) {
	if e == nil {
		return
	}

	switch eventIdentifier(e) {
	case "I7_HTTP_PLAINTEXT":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "暗号化されていない通信を検出しました",
			message:   "この端末は暗号化されていない HTTP 通信を使っています。通信内容が第三者に見られる可能性があります。",
			impact:    "ログイン情報や設定情報が含まれていた場合、後から見直されたり悪用されたりする可能性があります。",
			actionIDs: []string{"ENABLE_HTTPS", "UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	case "I7_HTTP_AUTH", "I7_HTTP_COOKIE", "I7_HTTP_TOKEN", "I7_HTTP_BODY_SECRET":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "認証や設定に関わる情報が通信に含まれている可能性があります",
			message:   "この端末の通信に、ログインや設定変更に関わる情報が含まれている可能性があります。安全な通信設定になっているか確認してください。",
			impact:    "通信経路が保護されていない場合、アカウントや端末設定の見直しが必要になる場合があります。",
			actionIDs: []string{"ENABLE_HTTPS", "CHANGE_DEFAULT_PASSWORD", "REVIEW_VENDOR_APP"},
		})
	case "I7_TELNET_PLAINTEXT", "I7_TELNET_CREDENTIALS":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "古い管理通信が使われている可能性があります",
			message:   "この端末で Telnet のような暗号化されていない管理通信が観測されました。家庭内でも慎重に扱った方がよい状態です。",
			impact:    "管理用の通信や認証情報が見られる可能性があり、端末設定を変更されるきっかけになる場合があります。",
			actionIDs: []string{"DISABLE_UNUSED_SERVICE", "CHANGE_DEFAULT_PASSWORD", "UPDATE_FIRMWARE"},
		})
	case "I7_MQTT_PLAINTEXT", "I7_MQTT_CREDENTIALS":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "IoT 通信の保護が弱い可能性があります",
			message:   "この端末は MQTT 通信を保護なしで使っている可能性があります。対応機器であれば暗号化設定を確認してください。",
			impact:    "メッセージ内容や認証情報が見える状態だと、操作内容や接続先が推測される場合があります。",
			actionIDs: []string{"ENABLE_HTTPS", "UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	case "I2_INSECURE_SERVICE", "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "安全性の低い機能が有効かもしれません",
			message:   "この端末で、古い管理機能や暗号化されていない機能が有効になっている可能性があります。使っていない機能を見直してください。",
			impact:    "不要な機能が残っていると、家庭内ネットワークから操作されたり情報を見られたりする可能性があります。",
			actionIDs: []string{"DISABLE_UNUSED_SERVICE", "UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	case "I4_INSECURE_FIRMWARE_UPDATE_HTTP", "I4_FIRMWARE_UPDATE_OBSERVED":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "更新通信の保護を確認してください",
			message:   "この端末の更新通信が観測されました。安全な更新方法が使われているか、メーカー情報で確認することをおすすめします。",
			impact:    "更新通信の保護が弱い場合、古い状態のまま使い続けたり、更新経路の確認が必要になったりします。",
			actionIDs: []string{"UPDATE_FIRMWARE", "ENABLE_HTTPS", "REVIEW_VENDOR_APP"},
		})
	case "I4_WEAK_UPDATE_VISIBILITY", "I4_FIRMWARE_RISK_ENRICHMENT", "I4_SUSPICIOUS_UPDATE_SOURCE":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "更新方法の確認をおすすめします",
			message:   "この端末は更新まわりの確認が必要かもしれません。メーカーの案内や設定画面で、更新方法を見直してください。",
			impact:    "更新状態が分かりにくい端末は、長期間そのまま使われる可能性があります。",
			actionIDs: []string{"UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	case "I5_KNOWN_VULNERABLE_COMPONENT":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "既知の脆弱性に関連する可能性があります",
			message:   "この端末の機種や通信の特徴が、既知の脆弱性情報と近い可能性があります。機種名や更新状況を確認してください。",
			impact:    "実際の機種が一致していた場合、更新や設定見直しが必要になる可能性があります。",
			actionIDs: []string{"UPDATE_FIRMWARE", "CHANGE_DEFAULT_PASSWORD", "REVIEW_VENDOR_APP"},
		})
	case "R1_COMPOSITE_RISK":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "複数の注意信号が重なっています",
			message:   "この端末から、いくつかの高リスクシグナルが重なって観測されました。すぐに断定はできませんが、端末の確認をおすすめします。",
			impact:    "放置すると、設定不備や情報露出の見逃しにつながる可能性があります。",
			actionIDs: []string{"CONFIRM_DEVICE_OWNER", "UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	case "I8_NEW_DEVICE_OBSERVED":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "新しい端末が接続されました",
			message:   "このネットワークで初めて見る端末です。自分や家族の端末か確認してください。",
			impact:    "心当たりがない端末の場合、家庭内ネットワークを利用されている可能性があります。",
			actionIDs: []string{"CONFIRM_DEVICE_OWNER", "LABEL_DEVICE", "ISOLATE_DEVICE"},
		})
	case "I8_UNREGISTERED_DEVICE_ACTIVE":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "未確認の端末が活動しています",
			message:   "既知端末リストに登録されていない端末が通信しています。所有している端末か確認してください。",
			impact:    "端末の正体が分からないままだと、後で重要な通知を見分けにくくなる可能性があります。",
			actionIDs: []string{"CONFIRM_DEVICE_OWNER", "LABEL_DEVICE", "ISOLATE_DEVICE"},
		})
	case "R1_QUARANTINE_RECOMMENDATION":
		applyUserGuidanceTemplate(e, userGuidanceTemplate{
			title:     "この端末は隔離候補です",
			message:   "この端末から複数の高リスクな通信が観測されました。心当たりがない場合は、一時的に通信を制限することを検討してください。",
			impact:    "放置すると、認証情報や設定情報が漏れる可能性があります。ただし、隔離すると端末の一部機能が使えなくなる場合があります。",
			actionIDs: []string{"CONFIRM_DEVICE_OWNER", "ISOLATE_DEVICE", "UPDATE_FIRMWARE", "REVIEW_VENDOR_APP"},
		})
	}

	AttachUserActions(e, catalog)
}

func AttachUserActions(e *Event, catalog knowledge.UserActionCatalog) {
	if e == nil {
		return
	}

	e.ActionIDs = dedupeNonEmptyStrings(e.ActionIDs)
	if len(e.ActionIDs) == 0 || len(catalog) == 0 {
		return
	}

	actions := make([]UserAction, 0, len(e.ActionIDs))
	for idx, actionID := range e.ActionIDs {
		def, ok := catalog[actionID]
		if !ok {
			continue
		}
		actions = append(actions, UserAction{
			ID:          actionID,
			Label:       strings.TrimSpace(def.Label),
			Description: strings.TrimSpace(def.Description),
			Difficulty:  strings.TrimSpace(def.Difficulty),
			Priority:    idx + 1,
			Fallback:    strings.TrimSpace(def.Fallback),
		})
	}

	if len(actions) == 0 {
		return
	}
	sort.SliceStable(actions, func(i, j int) bool {
		return actions[i].Priority < actions[j].Priority
	})
	e.UserActions = actions
}

func eventIdentifier(e *Event) string {
	if e == nil {
		return ""
	}
	if value := strings.TrimSpace(e.RuleID); value != "" {
		return value
	}
	return strings.TrimSpace(e.Type)
}

func applyUserGuidanceTemplate(e *Event, template userGuidanceTemplate) {
	if e == nil {
		return
	}
	if strings.TrimSpace(e.UserTitle) == "" {
		e.UserTitle = template.title
	}
	if strings.TrimSpace(e.UserMessage) == "" {
		e.UserMessage = template.message
	}
	if strings.TrimSpace(e.UserImpact) == "" {
		e.UserImpact = template.impact
	}
	if len(e.ActionIDs) == 0 {
		e.ActionIDs = append([]string(nil), template.actionIDs...)
	}
}

func dedupeNonEmptyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
