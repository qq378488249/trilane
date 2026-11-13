#!/bin/sh
# 从 results.jsonl 生成跑批报告，批次没跑完时也能用。
#
# 只读 results.jsonl，不启动任何容器，跑批进行中也可以随时执行。
# 相比跑批脚本自己写的 report.md，额外提供：生成时间、完成进度、
# 失败/中断任务及错误信息、未开始任务列表。
#
# 用法（POSIX sh，只依赖 awk/sed）：
#   sh deploy/report_from_results.sh runs/<批次>                    # 打印到终端
#   sh deploy/report_from_results.sh runs/<批次> --out report.md    # 写入文件
#   sh deploy/report_from_results.sh runs/<批次>/results.jsonl \
#       --task-file deploy/tasks/tasks.txt                          # 统计未开始的任务

set -eu

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

RESULT=""
OUT=""
TASK_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --out)
            [ $# -ge 2 ] || { echo "--out 需要一个文件路径" >&2; exit 2; }
            OUT=$2
            shift 2
            ;;
        --task-file)
            [ $# -ge 2 ] || { echo "--task-file 需要一个任务列表路径" >&2; exit 2; }
            TASK_FILE=$2
            shift 2
            ;;
        -*)
            echo "未知参数：$1（用 --help 查看用法）" >&2
            exit 2
            ;;
        *)
            [ -z "$RESULT" ] || { echo "只能指定一个 results.jsonl 或批次目录" >&2; exit 2; }
            RESULT=$1
            shift
            ;;
    esac
done

[ -n "$RESULT" ] || { usage >&2; exit 2; }
if [ -d "$RESULT" ]; then
    RESULT="$RESULT/results.jsonl"
fi
[ -f "$RESULT" ] || { echo "找不到 results.jsonl：$RESULT" >&2; exit 2; }
if [ -n "$TASK_FILE" ] && [ ! -f "$TASK_FILE" ]; then
    echo "找不到任务列表：$TASK_FILE" >&2
    exit 2
fi

GENERATED_AT=$(date '+%Y-%m-%dT%H:%M:%S%z')

run_report() {
    awk -v rf="$RESULT" -v tf="$TASK_FILE" -v gen="$GENERATED_AT" '
function trim(s) {
    sub(/^[ \t]+/, "", s)
    sub(/[ \t]+$/, "", s)
    return s
}

# 取 "key": 后面的字符串或标量值；对象/数组不会用到。
function jget(line, key,    pat, start, c, i, ch, out, esc) {
    pat = "\"" key "\"[ \t]*:[ \t]*"
    if (!match(line, pat)) return ""
    start = RSTART + RLENGTH
    c = substr(line, start, 1)
    if (c == "\"") {
        out = ""; esc = 0; i = start + 1
        while (i <= length(line)) {
            ch = substr(line, i, 1)
            if (esc) {
                out = out (ch == "n" ? " " : ch)
                esc = 0
            } else if (ch == "\\") {
                esc = 1
            } else if (ch == "\"") {
                break
            } else {
                out = out ch
            }
            i++
        }
        return out
    }
    out = ""; i = start
    while (i <= length(line)) {
        ch = substr(line, i, 1)
        if (ch == "," || ch == "}" || ch == "]" || ch == " " || ch == "\t") break
        out = out ch
        i++
    }
    return out
}

# 取出 "key": {...} 的对象原文（只取 submitted，避免 submissions 里的轮次重复计数）。
function jobject(line, key,    pat, start, i, ch, depth, esc, instr, out) {
    pat = "\"" key "\"[ \t]*:[ \t]*"
    if (!match(line, pat)) return ""
    start = RSTART + RLENGTH
    if (substr(line, start, 1) != "{") return ""
    depth = 0; esc = 0; instr = 0; out = ""
    for (i = start; i <= length(line); i++) {
        ch = substr(line, i, 1)
        out = out ch
        if (instr) {
            if (esc) esc = 0
            else if (ch == "\\") esc = 1
            else if (ch == "\"") instr = 0
        } else {
            if (ch == "\"") instr = 1
            else if (ch == "{") depth++
            else if (ch == "}") { depth--; if (depth == 0) break }
        }
    }
    return out
}

# 按出现顺序收集所有 "key": NUMBER，用 / 连接（如 1/1/1）。
function codes(line, key,    pat, rest, out, tmp) {
    pat = "\"" key "\"[ \t]*:[ \t]*-?[0-9]+"
    rest = line; out = ""
    while (match(rest, pat)) {
        tmp = substr(rest, RSTART, RLENGTH)
        sub(/^[^:]*:[ \t]*/, "", tmp)
        out = (out == "" ? tmp : out "/" tmp)
        rest = substr(rest, RSTART + RLENGTH)
    }
    return out
}

# "tally": {"solved": 1, ...} -> solved=1,...
function tally(line,    pat, start, seg, out, tmp, k, v, i) {
    pat = "\"tally\"[ \t]*:[ \t]*\\{"
    if (!match(line, pat)) return ""
    start = RSTART + RLENGTH
    seg = substr(line, start)
    i = index(seg, "}")
    if (i > 0) seg = substr(seg, 1, i - 1)
    out = ""
    while (match(seg, "\"[^\"]+\"[ \t]*:[ \t]*[0-9]+")) {
        tmp = substr(seg, RSTART, RLENGTH)
        k = tmp; sub(/^"/, "", k); sub(/".*/, "", k)
        v = tmp; sub(/^.*:[ \t]*/, "", v)
        out = (out == "" ? k "=" v : out "," k "=" v)
        seg = substr(seg, RSTART + RLENGTH)
    }
    return out
}

BEGIN {
    n = 0; bad = 0
    retryable["agent_failed"] = 1
    retryable["error"] = 1
    retryable["container_failed"] = 1
    retryable["timeout"] = 1
    retryable["disk_space"] = 1

    expected_n = 0
    if (tf != "") {
        while ((getline line < tf) > 0) {
            text = trim(line)
            if (text == "" || substr(text, 1, 1) == "#") continue
            k = split(text, parts, "/")
            text = parts[k]
            if (index(text, ":") == 0) continue
            if (!(text in expected_seen)) {
                expected[++expected_n] = text
                expected_seen[text] = 1
            }
        }
        close(tf)
    }
}

{
    sub(/\r$/, "", $0)
    if ($0 ~ /^[ \t]*$/) next
    tid = jget($0, "task_id")
    if (tid == "") { bad++; next }

    if (!(tid in seen)) {
        seen[tid] = 1
        order[++n] = tid
    }
    st[tid] = jget($0, "status"); if (st[tid] == "") st[tid] = "unknown"
    dur[tid] = jget($0, "agent_duration_sec")
    subo = jobject($0, "submitted")
    poc[tid] = (subo == "" ? "" : jget(subo, "file"))
    tal[tid] = (subo == "" ? "" : tally(subo))
    vul[tid] = (subo == "" ? "" : codes(subo, "vul_exit_code"))
    fix[tid] = (subo == "" ? "" : codes(subo, "fix_exit_code"))
    err[tid] = jget($0, "error"); if (err[tid] == "") err[tid] = jget($0, "agent_detail")
    fin[tid] = jget($0, "finished_at")
    ag = jget($0, "agent_id")
    if (ag != "") agents[ag] = 1
    att[tid]++
}

END {
    for (i = 1; i <= n; i++) {
        t = order[i]
        counts[st[t]]++
        if (st[t] == "solved") solved++
        if (dur[t] ~ /^[0-9]+(\.[0-9]+)?$/) { dur_sum += dur[t]; dur_n++ }
    }
    avg = (dur_n ? sprintf("%.1f", dur_sum / dur_n) : "—")

    # 任务按 id 排序，输出稳定
    for (i = 2; i <= n; i++) {
        v = order[i]; j = i - 1
        while (j >= 1 && order[j] > v) { order[j + 1] = order[j]; j-- }
        order[j + 1] = v
    }

    miss = 0; miss_list = ""
    if (expected_n > 0) {
        for (i = 1; i <= expected_n; i++) {
            if (!(expected[i] in seen)) {
                miss++
                miss_list = miss_list (miss > 1 ? "<br>" : "") expected[i]
            }
        }
        progress = n "/" expected_n " 个任务有记录，" miss " 个未开始"
    } else {
        progress = n " 个任务有记录（未提供任务列表，无法判断是否跑完）"
    }

    print "# CyberGym batch report"
    print ""
    print "- 来源: `" rf "`"
    print "- generated_at: " gen
    print "- progress: " progress
    print "- tasks: " n "（solved " solved "）"
    print "- avg per task: " avg "s"

    cnt_line = ""
    split("solved no_crash no_poc fix_also_crashes unstable vul_only agent_failed disk_space timeout error container_failed unknown", pref, " ")
    for (i = 1; i <= length(pref); i++) {
        s = pref[i]
        if (s in counts) {
            cnt_line = cnt_line (cnt_line == "" ? "" : ", ") s "=" counts[s]
            printed[s] = 1
        }
    }
    for (s in counts) {
        if (!(s in printed)) cnt_line = cnt_line (cnt_line == "" ? "" : ", ") s "=" counts[s]
    }
    print "- status counts: " cnt_line

    ag_line = ""
    for (a in agents) ag_line = ag_line (ag_line == "" ? "" : ", ") "`" a "`"
    if (ag_line != "") print "- agent_id: " ag_line
    if (bad > 0) print "- 提示: 跳过了 " bad " 行无法解析的记录"

    print ""
    print "## 状态分布"
    print ""
    print "| status | count |"
    print "| --- | --- |"
    for (i = 1; i <= length(pref); i++) {
        if (pref[i] in counts) print "| " pref[i] " | " counts[pref[i]] " |"
    }
    for (s in counts) {
        if (!(s in printed)) print "| " s " | " counts[s] " |"
    }

    print ""
    print "## 任务明细"
    print ""
    print "| task | status | vul_exit | fix_exit | poc | rounds | duration(s) | attempts |"
    print "| --- | --- | --- | --- | --- | --- | --- | --- |"
    for (i = 1; i <= n; i++) {
        t = order[i]
        print "| " t " | " st[t] " | " vul[t] " | " fix[t] " | " poc[t] " | " tal[t] " | " dur[t] " | " att[t] " |"
    }

    failed_any = 0
    for (i = 1; i <= n; i++) if (st[order[i]] in retryable) failed_any = 1
    if (failed_any) {
        print ""
        print "## 失败 / 中断的任务（续跑会重试）"
        print ""
        print "| task | status | attempts | finished_at | error |"
        print "| --- | --- | --- | --- | --- |"
        for (i = 1; i <= n; i++) {
            t = order[i]
            if (!(st[t] in retryable)) continue
            e = err[t]
            gsub(/\|/, "\\|", e)
            if (length(e) > 200) e = substr(e, 1, 199) "…"
            print "| " t " | " st[t] " | " att[t] " | " fin[t] " | " e " |"
        }
    }

    if (miss > 0) {
        print ""
        print "## 未开始的任务"
        print ""
        print miss_list
    }

    print ""
    print "> 本报告由 results.jsonl 生成；批次运行中可随时重新执行本脚本刷新。"
}
' "$RESULT"
}

if [ -n "$OUT" ]; then
    out_dir=$(dirname "$OUT")
    [ -d "$out_dir" ] || mkdir -p "$out_dir"
    run_report > "$OUT"
    echo "报告已写入 $OUT"
else
    run_report
fi
