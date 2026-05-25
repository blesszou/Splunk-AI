require([
    "splunkjs/mvc",
    "splunkjs/mvc/searchmanager",
    "jquery"
], function(mvc, SearchManager, $) {

    // ----------------------------------------------------------------
    // 1. Inject drawer HTML into the page body
    // ----------------------------------------------------------------
    $('body').append(`
        <div id="ai-drawer-overlay"></div>
        <div id="ai-drawer-panel">

            <div id="ai-drawer-header">
                <div>
                    <div class="drawer-subtitle">Splunk AI · Log Analyst</div>
                    <h2>🤖 AI Assistant</h2>
                </div>
                <button id="close-ai-drawer" title="Close">✕</button>
            </div>

            <div id="ai-drawer-status-bar">
                <span id="ai-drawer-status-text">Waiting for data search to complete...</span>
                <button id="ai-drawer-clear-btn" title="Clear conversation history">🗑 Clear History</button>
            </div>

            <div id="ai-drawer-prompt-area">
                <textarea id="ai-drawer-prompt"
                    placeholder="Ask a question about the log data shown in the table...&#10;e.g. Summarize the top errors and suggest root causes&#10;&#10;Ctrl+Enter to submit"></textarea>
                <div id="ai-drawer-prompt-controls">
                    <select id="ai-drawer-provider" title="LLM provider from agent_config.conf">
                        <option value="ollama">🦙 Ollama</option>
                        <option value="gemini">✨ Gemini</option>
                    </select>
                    <button id="ai-drawer-run-btn" disabled>▶ Analyze</button>
                </div>
            </div>

            <div id="ai-chat-content">
                <div class="drawer-placeholder">
                    <div class="placeholder-icon">🔍</div>
                    <p>Run a data search in the left panel first.<br/>Once it completes, type your question here and click <strong>▶ Analyze</strong>.</p>
                </div>
            </div>
        </div>
    `);

    // ----------------------------------------------------------------
    // 2. React to base_sid token — enable/disable the Run button
    // ----------------------------------------------------------------
    var defaultTokens = mvc.Components.getInstance("default");

    function syncStatus() {
        var sid = defaultTokens.get("base_sid");
        var $btn = $("#ai-drawer-run-btn");
        var $statusText = $("#ai-drawer-status-text");
        if (sid) {
            $btn.prop("disabled", false);
            $statusText.html('✅ <strong>' + sid + '</strong> — data ready, ask your question below');
            $statusText.css("color", "#4ade80");
        } else {
            $btn.prop("disabled", true);
            $statusText.text("⏳ Waiting for data search to complete...");
            $statusText.css("color", "#f59e0b");
        }
    }

    defaultTokens.on("change:base_sid", syncStatus);
    syncStatus(); // run once on load

    // ----------------------------------------------------------------
    // 3. Open / Close drawer
    // ----------------------------------------------------------------
    function openDrawer() {
        syncStatus();
        $("#ai-drawer-overlay").fadeIn(200);
        $("#ai-drawer-panel").addClass("open");
    }

    function closeDrawer() {
        $("#ai-drawer-overlay").fadeOut(200);
        $("#ai-drawer-panel").removeClass("open");
    }

    $(document).on("click", "#btn-open-ai", openDrawer);
    $(document).on("click", "#close-ai-drawer, #ai-drawer-overlay", closeDrawer);

    // ----------------------------------------------------------------
    // 4. Clear history — reset session token
    // ----------------------------------------------------------------
    $(document).on("click", "#ai-drawer-clear-btn", function() {
        var newSession = "data_chat_" + Date.now();
        defaultTokens.set("session_tok", newSession);
        $("#ai-chat-content").html(`
            <div class="drawer-placeholder">
                <div class="placeholder-icon">🗑️</div>
                <p>Conversation history cleared. Start a new question below.</p>
            </div>
        `);
    });

    // ----------------------------------------------------------------
    // 5. Trigger analysis
    // ----------------------------------------------------------------
    $(document).on("click", "#ai-drawer-run-btn", function() {
        var prompt = $("#ai-drawer-prompt").val().trim();
        if (prompt) runLLMChat(prompt);
    });

    $(document).on("keydown", "#ai-drawer-prompt", function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            var prompt = $(this).val().trim();
            if (prompt) runLLMChat(prompt);
        }
    });

    // ----------------------------------------------------------------
    // 6. Core: run | loadjob <base_sid> | llmchat ... via JS SDK
    // ----------------------------------------------------------------
    function runLLMChat(promptText) {
        var baseSid    = defaultTokens.get("base_sid");
        var sessionTok = defaultTokens.get("session_tok") || ("data_chat_" + Date.now());
        var $content   = $("#ai-chat-content");

        if (!baseSid) {
            $content.html(makeRow("error", "⚠️ No Data Loaded",
                "Please run the SPL search in the left panel first, then ask your question."));
            return;
        }

        // Show loading state
        $content.html(`
            <div class="drawer-loading">
                <div class="drawer-spinner"></div>
                <span>AI is reading your logs and thinking...</span>
            </div>
        `);

        // Sanitize the prompt for inline SPL (no double-quotes, no $ signs)
        var safePrompt = promptText.replace(/"/g, "'").replace(/\$/g, "");

        var provider    = $("#ai-drawer-provider").val() || "ollama";

        var spl = '| loadjob ' + baseSid +
                  ' | llmchat session="' + sessionTok + '" prompt="' + safePrompt + '" provider="' + provider + '"' +
                  ' | eval chat_history=coalesce(chat_history, "")' +
                  ' | eval ai_response=if(isnull(ai_response), "(no response)", ai_response)';

        var searchId = "ai_drawer_llmchat_" + Date.now();
        var aiSearch = new SearchManager({
            id: searchId,
            autostart: true,
            search: spl,
            preview: false
        });

        var results = aiSearch.data("results", { count: 0, output_mode: "json" });

        results.on("data", function() {
            var data = results.data().results;
            if (!data || data.length === 0) return;

            var row          = data[0];
            var aiResponse   = String(row.ai_response   || "(no response)");
            var chatHistory  = String(row.chat_history  || "");
            var analyzedCnt  = String(row.analyzed_count || "?");
            var userPrompt   = String(row.user_prompt   || promptText);
            var providerUsed = String(row.provider || provider || "?");
            var modelUsed    = String(row.model    || "");

            var html = "";

            // User bubble
            html += '<div class="drawer-bubble drawer-bubble-user">' +
                        '<strong>🧑‍💻 You</strong>' +
                        '<div class="bubble-body">' + escHtml(userPrompt) + '</div>' +
                    '</div>';

            // AI answer bubble
            html += '<div class="drawer-bubble drawer-bubble-ai">' +
                        '<strong>🤖 AI Log Analyst</strong>' +
                        '<div class="bubble-body">' + escHtml(aiResponse) + '</div>' +
                        '<span class="drawer-stats">✓ Analyzed ' + escHtml(analyzedCnt) + ' events &nbsp;·&nbsp; ' +
                        escHtml(providerUsed) + (modelUsed ? ' / ' + escHtml(modelUsed) : '') + '</span>' +
                    '</div>';

            // History divider + bubble (if non-empty)
            if (chatHistory && chatHistory.trim() !== "") {
                html += '<div class="drawer-history-sep">─── Previous Chat History ───</div>';
                html += '<div class="drawer-bubble drawer-bubble-history">' +
                            '<div class="bubble-body">' + escHtml(chatHistory) + '</div>' +
                        '</div>';
            }

            $content.html(html);
            $content.scrollTop(0); // show latest at top
        });

        aiSearch.on("search:done", function(state) {
            if (state.content.resultCount === 0) {
                $content.html(makeRow("error", "⚠️ No Results",
                    "The LLM search returned 0 rows. Check that the llmchat command is installed and the LLM endpoint is reachable."));
            }
        });

        aiSearch.on("search:failed", function() {
            $content.html(makeRow("error", "❌ Search Failed",
                "The LLM job failed. Check the llmchat command configuration and your LLM endpoint."));
        });

        aiSearch.on("search:error", function(state) {
            var msgs = (state && state.content && state.content.messages) ?
                JSON.stringify(state.content.messages) : "Unknown error";
            $content.html(makeRow("error", "❌ Error", msgs));
        });
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    function escHtml(str) {
        return $("<div>").text(String(str)).html();
    }

    function makeRow(type, label, body) {
        return '<div class="drawer-row drawer-row-' + type + '">' +
                   '<strong>' + label + '</strong>' +
                   escHtml(body) +
               '</div>';
    }
});