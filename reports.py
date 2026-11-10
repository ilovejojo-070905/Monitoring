"""3-2 보고서 내보내기 -- PDF (reportlab) and Excel (openpyxl) generation for
the 3 report types the ticket asks for: 장애 이력, 자원 사용률, 네트워크 상태.

Korean rendering (PDF): reportlab's built-in fonts are Latin-1 only, so
Correct 한글 output requires registering a real CJK-capable TTF -- 맑은 고딕
(Malgun Gothic), which ships with every Windows install since Windows 7, at
C:\\Windows\\Fonts\\malgun.ttf (+ malgunbd.ttf for bold). This was verified
end-to-end during development: generate a PDF, extract its text back out
with a PDF reader, and confirm the Korean round-trips character-for-character
rather than becoming boxes/mojibake -- not just that the file "looks okay".

Table page-breaks: built via reportlab's platypus layer (SimpleDocTemplate +
Table), not the raw low-level canvas API -- platypus's Table.split() handles
pagination automatically when a table doesn't fit on one page, including
repeating the header row on each continuation page (`repeatRows=1`). Hand-
rolling pagination against the canvas API directly would mean re-implementing
exactly this, with much more room for a subtle bug (a row silently clipped at
a page boundary) that's easy to miss without opening the output in a real PDF
reader. This too was verified: an 80-row test table split cleanly across 3
pages with the header repeated on each.
"""
import io
import os
import time
import unicodedata

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.platypus.flowables import HRFlowable

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

import storage
import validation
from collector import sla
from collector.thresholds import FALLBACK_THRESHOLDS

_FONT_REGISTERED = False
# Only Windows paths -- this whole app is Windows-only already (IS_WINDOWS
# gates elsewhere throughout storage.py/collector/*), so there's no non-
# Windows fallback to maintain.
_KOREAN_FONT_CANDIDATES = [
    (r'C:\Windows\Fonts\malgun.ttf', r'C:\Windows\Fonts\malgunbd.ttf'),
]


def _ensure_korean_font():
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return
    for regular, bold in _KOREAN_FONT_CANDIDATES:
        if os.path.exists(regular) and os.path.exists(bold):
            pdfmetrics.registerFont(TTFont('Korean', regular))
            pdfmetrics.registerFont(TTFont('KoreanBold', bold))
            _FONT_REGISTERED = True
            return
    raise RuntimeError('한글 글꼴(맑은 고딕)을 찾을 수 없어 PDF를 생성할 수 없습니다')


def _fmt_ms(ms):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ms / 1000)) if ms else '-'


def _fmt_duration(ms):
    if ms is None:
        return '-'
    total_min = round(ms / 60000)
    days, rem = divmod(total_min, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        return f'{days}일 {hours}시간'
    if hours:
        return f'{hours}시간 {mins}분'
    return f'{mins}분'


def _resolve_devices(device_id=None, group=None):
    devices = storage.load_devices()
    if device_id:
        return [d for d in devices if d['id'] == device_id]
    if group:
        return [d for d in devices if (d.get('fields') or {}).get('group') == group]
    return devices


def _filter_desc(device_id=None, group=None):
    if device_id:
        d = storage.load_device(device_id)
        return f"대상 장비: {d['name']}" if d else f"대상 장비: {device_id}"
    if group:
        return f"대상 그룹: {group}"
    return '대상: 전체 장비'


# --------------------------------------------------------- 시각적 보강 --
# 사용자 피드백("가동률 보고서 내보내기 PDF 받으면 너무 단조로워"): 기존엔
# 제목+메타 3줄+표 하나뿐이라 전부 같은 회색 글씨였다. 표 아래에 상태/
# 심각도/가동률처럼 등급이 있는 값은 화면(웹) 쪽과 동일한 기준(아래 색상 ·
# uptimePillClass 색상, FALLBACK_THRESHOLDS cpu/mem/disk 경계값)으로
# 색을 입히고, 표 위에 핵심 숫자를 바로 보여주는 "요약" 카드 한 줄과
# 페이지마다 상단 브랜드 띠 · 하단 페이지 번호를 추가했다.
GRADE_COLOR = {'good': '#00b087', 'warn': '#e6960f', 'crit': '#ef3b5c'}


def _grade_uptime(pct):
    if pct is None:
        return None
    if pct >= 99.9:
        return 'good'
    if pct >= 99:
        return 'warn'
    return 'crit'


def _grade_resource(value, kind):
    if value is None:
        return None
    th = FALLBACK_THRESHOLDS[kind]
    if value >= th['crit']:
        return 'crit'
    if value >= th['warn']:
        return 'warn'
    return 'good'


_CELL_STYLE = ParagraphStyle('kr_cell', fontName='Korean', fontSize=8.5, leading=11, textColor=colors.HexColor('#333333'))
_CELL_CRIT = ParagraphStyle('kr_cell_crit', parent=_CELL_STYLE, fontName='KoreanBold', textColor=colors.HexColor(GRADE_COLOR['crit']))
_CELL_WARN = ParagraphStyle('kr_cell_warn', parent=_CELL_STYLE, fontName='KoreanBold', textColor=colors.HexColor(GRADE_COLOR['warn']))
_CELL_GOOD = ParagraphStyle('kr_cell_good', parent=_CELL_STYLE, textColor=colors.HexColor(GRADE_COLOR['good']))
_CELL_INFO = ParagraphStyle('kr_cell_info', parent=_CELL_STYLE, textColor=colors.HexColor('#5b6478'))

SEVERITY_CELL_STYLE = {'위험': _CELL_CRIT, '주의': _CELL_WARN, '정보': _CELL_INFO}
STATUS_CELL_STYLE = {'미해결': _CELL_CRIT, '확인됨': _CELL_WARN, '해결됨': _CELL_GOOD}
UPTIME_CELL_STYLE = {'good': _CELL_GOOD, 'warn': _CELL_WARN, 'crit': _CELL_CRIT}


def _cell_paragraph(report_type, ci, value):
    text = validation.escape_pdf_text(str(value))
    if report_type == 'incident':
        if ci == 3 and value in SEVERITY_CELL_STYLE:
            return Paragraph(text, SEVERITY_CELL_STYLE[value])
        if ci == 4 and value in STATUS_CELL_STYLE:
            return Paragraph(text, STATUS_CELL_STYLE[value])
    elif report_type == 'network' and ci == 2 and value != '-':
        try:
            grade = _grade_uptime(float(value))
        except ValueError:
            grade = None
        if grade:
            return Paragraph(text, UPTIME_CELL_STYLE[grade])
    return Paragraph(text, _CELL_STYLE)


def _avg_col(rows, idx):
    vals = []
    for r in rows:
        if r[idx] != '-':
            try:
                vals.append(float(r[idx]))
            except ValueError:
                pass
    return sum(vals) / len(vals) if vals else None


def _build_summary(report_type, rows):
    """표 본문 위에 보여줄 핵심 숫자 카드(최대 4개) -- (라벨, 값문자열, 등급|None, 보조라벨|None).
    보조라벨은 값 아래 작은 글씨로 덧붙는 장비명 등 -- 긴 장비명을 값 문자열에
    그대로 붙이면(예: "DESKTOP-938NHR6 (100.0%)") 카드 폭이 좁아 단어 중간에서
    줄바꿈돼 깨지므로, 숫자(값)와 장비명(보조라벨)을 분리해 각자 알맞은
    글자 크기로 렌더링한다."""
    if report_type == 'incident':
        total = len(rows)
        unresolved = sum(1 for r in rows if r[4] == '미해결')
        critical = sum(1 for r in rows if r[3] == '위험')
        cat_counts = {}
        for r in rows:
            cat_counts[r[2]] = cat_counts.get(r[2], 0) + 1
        top_cat = max(cat_counts, key=cat_counts.get) if cat_counts else '-'
        return [
            ('전체 장애 건수', str(total), None, None),
            ('미해결', str(unresolved), 'crit' if unresolved else 'good', None),
            ('위험 등급', str(critical), 'crit' if critical else 'good', None),
            ('최다 발생 분류', top_cat, None, None),
        ]
    if report_type == 'resource':
        cpu_avg, mem_avg, disk_avg = _avg_col(rows, 1), _avg_col(rows, 3), _avg_col(rows, 5)
        candidates = []
        for r in rows:
            if r[2] != '-':
                try:
                    candidates.append((r[0], float(r[2])))
                except ValueError:
                    pass
        worst = max(candidates, key=lambda x: x[1]) if candidates else None
        return [
            ('평균 CPU', f'{cpu_avg:.1f}%' if cpu_avg is not None else '-', _grade_resource(cpu_avg, 'cpu'), None),
            ('평균 메모리', f'{mem_avg:.1f}%' if mem_avg is not None else '-', _grade_resource(mem_avg, 'mem'), None),
            ('평균 디스크', f'{disk_avg:.1f}%' if disk_avg is not None else '-', _grade_resource(disk_avg, 'disk'), None),
            ('최고 CPU 장비', f'{worst[1]:.1f}%' if worst else '-', _grade_resource(worst[1], 'cpu') if worst else None,
             worst[0] if worst else None),
        ]
    if report_type == 'network':
        pct_pairs = []
        for r in rows:
            if r[2] != '-':
                try:
                    pct_pairs.append((r[0], float(r[2])))
                except ValueError:
                    pass
        avg_pct = sum(v for _, v in pct_pairs) / len(pct_pairs) if pct_pairs else None
        total_fail = sum(int(r[3]) for r in rows)
        worst = min(pct_pairs, key=lambda x: x[1]) if pct_pairs else None
        return [
            ('평균 가동률', f'{avg_pct:.3f}%' if avg_pct is not None else '-', _grade_uptime(avg_pct), None),
            ('총 장애 횟수', str(total_fail), 'crit' if total_fail else 'good', None),
            ('대상 장비 수', str(len(rows)), None, None),
            ('최저 가동률 장비', f'{worst[1]:.3f}%' if worst else '-', _grade_uptime(worst[1]) if worst else None,
             worst[0] if worst else None),
        ]
    return []


def _build_summary_table(summary_items, usable_mm):
    label_style = ParagraphStyle('kr_sum_label', fontName='Korean', fontSize=8, leading=10, textColor=colors.HexColor('#5b6478'))
    sublabel_style = ParagraphStyle('kr_sum_sublabel', fontName='Korean', fontSize=8, leading=10, textColor=colors.HexColor('#8d93a6'))
    cmds = [
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f7f8fb')),
        ('BOX', (0, 0), (-1, -1), 0.4, colors.HexColor('#e3e6ee')),
        ('INNERGRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e3e6ee')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]
    row = []
    for i, (label, value, grade, sublabel) in enumerate(summary_items):
        value_style = ParagraphStyle(f'kr_sum_val_{i}', fontName='KoreanBold', fontSize=13.5, leading=16,
                                      textColor=colors.HexColor(GRADE_COLOR.get(grade, '#1c2333')))
        cell = [
            Paragraph(validation.escape_pdf_text(label), label_style),
            Paragraph(validation.escape_pdf_text(value), value_style),
        ]
        if sublabel:
            cell.append(Paragraph(validation.escape_pdf_text(sublabel), sublabel_style))
        row.append(cell)
        cmds.append(('LINEABOVE', (i, 0), (i, 0), 2.6, colors.HexColor(GRADE_COLOR.get(grade, '#7c5cff'))))
    col_w = usable_mm / len(summary_items) * mm
    t = Table([row], colWidths=[col_w] * len(summary_items))
    t.setStyle(TableStyle(cmds))
    return t


# ------------------------------------------------------------ 데이터 수집 --
def gather_incident_report(start_ms, end_ms, device_id=None, group=None):
    devices = _resolve_devices(device_id, group)
    device_ids = {d['id'] for d in devices}
    conn = storage.get_db()
    rows = conn.execute(
        'SELECT * FROM incidents WHERE ts>=? AND ts<? ORDER BY ts DESC', (start_ms, end_ms)).fetchall()
    conn.close()
    out = []
    for r in rows:
        if r['device_id'] and r['device_id'] not in device_ids:
            continue
        if not r['device_id'] and (device_id or group):
            continue  # a device-less row (e.g. system-level) doesn't match a device/group filter
        out.append({
            'time': _fmt_ms(r['ts']), 'source': r['source'], 'category': r['category'],
            'severity': {'crit': '위험', 'warn': '주의', 'info': '정보'}.get(r['severity'], r['severity']),
            'status': {'open': '미해결', 'ack': '확인됨', 'resolved': '해결됨'}.get(r['status'], r['status']),
            'duration': _fmt_duration((r['resolved_at'] or end_ms) - r['first_occurred_at']) if r['first_occurred_at'] else '-',
            'message': r['message'],
        })
    columns = ['시각', '장비/출처', '분류', '심각도', '상태', '지속시간', '내용']
    table_rows = [[i['time'], i['source'], i['category'], i['severity'], i['status'], i['duration'], i['message']] for i in out]
    return columns, table_rows


def gather_resource_report(start_ms, end_ms, device_id=None, group=None):
    devices = _resolve_devices(device_id, group)
    columns = ['장비명', '평균 CPU %', '최대 CPU %', '평균 메모리 %', '최대 메모리 %', '평균 디스크 %', '최대 디스크 %']
    rows = []
    for d in devices:
        cpu = storage.summarize_metric_range(d['id'], 'cpu', start_ms, end_ms)
        mem = storage.summarize_metric_range(d['id'], 'mem', start_ms, end_ms)
        disk = storage.summarize_metric_range(d['id'], 'disk', start_ms, end_ms)
        if not (cpu or mem or disk):
            continue  # no resource data for this device in range (e.g. a ping-only device) -- omit rather than show all "-"
        def _a(m, key): return f"{m[key]:.1f}" if m else '-'
        rows.append([d['name'], _a(cpu, 'avg'), _a(cpu, 'max'), _a(mem, 'avg'), _a(mem, 'max'), _a(disk, 'avg'), _a(disk, 'max')])
    return columns, rows


def gather_network_report(start_ms, end_ms, device_id=None, group=None):
    """네트워크 상태 보고서: uptime/SLA figures scoped to category='net'
    devices specifically (switches/routers/APs) -- a device/group filter
    further narrows within that, same as the other two report types."""
    devices = [d for d in _resolve_devices(device_id, group) if d['category'] == 'net']
    columns = ['장비명', 'IP', '가동률 %', '장애 횟수', 'MTTR', 'MTBF', '점검 시간']
    rows = []
    for d in devices:
        r = sla.device_uptime_report(d, start_ms, end_ms)
        rows.append([d['name'], d.get('ip') or '-', f"{r['uptimePct']:.3f}", r['failureCount'],
                     _fmt_duration(r['mttrMs']), _fmt_duration(r['mtbfMs']), _fmt_duration(r['maintenanceMs'])])
    return columns, rows


_REPORT_TITLES = {
    'incident': '장애 이력 보고서', 'resource': '자원 사용률 보고서', 'network': '네트워크 상태 보고서',
}
_REPORT_GATHERERS = {
    'incident': gather_incident_report, 'resource': gather_resource_report, 'network': gather_network_report,
}


def build_pdf(report_type, start_ms, end_ms, device_id=None, group=None):
    _ensure_korean_font()
    columns, rows = _REPORT_GATHERERS[report_type](start_ms, end_ms, device_id, group)
    title = _REPORT_TITLES[report_type]
    period_desc = f"기간: {_fmt_ms(start_ms)} ~ {_fmt_ms(end_ms)}"
    filter_desc = _filter_desc(device_id, group)
    generated_at_ms = int(time.time() * 1000)

    title_style = ParagraphStyle('kr_title', fontName='KoreanBold', fontSize=18, leading=22, textColor=colors.HexColor('#1c2333'))
    meta_style = ParagraphStyle('kr_meta', fontName='Korean', fontSize=9.5, leading=14, textColor=colors.HexColor('#555555'))
    section_style = ParagraphStyle('kr_section', fontName='KoreanBold', fontSize=12, leading=15, textColor=colors.HexColor('#1c2333'))
    usable_mm = 210 - 28  # A4 폭(210mm) - 좌우 여백(14mm씩)

    def _decorate(canvas, doc_):
        # 페이지마다: 상단 브랜드 띠(InfraSight) + 하단 생성시각/페이지 번호.
        # 기존엔 페이지가 그냥 흰 배경에 표만 떠 있어 "단조롭다"는 피드백이
        # 있었음 -- 보고서 어디서 한 장만 봐도 어떤 시스템이 언제 만들었는지
        # 알 수 있게.
        canvas.saveState()
        page_w, page_h = A4
        canvas.setFillColor(colors.HexColor('#1c2333'))
        canvas.rect(0, page_h - 12 * mm, page_w, 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont('KoreanBold', 11)
        canvas.drawString(14 * mm, page_h - 8.3 * mm, 'InfraSight')
        canvas.setFont('Korean', 8)
        canvas.setFillColor(colors.HexColor('#c7ccdb'))
        canvas.drawRightString(page_w - 14 * mm, page_h - 8.1 * mm, '인프라 모니터링 시스템')
        canvas.setStrokeColor(colors.HexColor('#dddddd'))
        canvas.line(14 * mm, 15 * mm, page_w - 14 * mm, 15 * mm)
        canvas.setFillColor(colors.HexColor('#8d93a6'))
        canvas.setFont('Korean', 7.5)
        canvas.drawString(14 * mm, 10.5 * mm, f'생성: {_fmt_ms(generated_at_ms)}')
        canvas.drawRightString(page_w - 14 * mm, 10.5 * mm, f'{canvas.getPageNumber()} 페이지')
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=18 * mm, leftMargin=14 * mm, rightMargin=14 * mm)

    meta_box = Table([[[
        Paragraph(period_desc, meta_style),
        Paragraph(validation.escape_pdf_text(filter_desc), meta_style),
    ]]], colWidths=[usable_mm * mm])
    meta_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f7f8fb')),
        ('BOX', (0, 0), (-1, -1), 0.4, colors.HexColor('#e3e6ee')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10), ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
    ]))

    elements = [
        Paragraph(title, title_style),
        HRFlowable(width='100%', thickness=1.4, color=colors.HexColor('#7c5cff'), spaceBefore=3, spaceAfter=6),
        meta_box,
        Spacer(1, 7 * mm),
    ]
    if not rows:
        elements.append(Paragraph('해당 조건에 데이터가 없습니다.', meta_style))
    else:
        summary_items = _build_summary(report_type, rows)
        if summary_items:
            elements.append(Paragraph('요약', section_style))
            elements.append(Spacer(1, 2.5 * mm))
            elements.append(_build_summary_table(summary_items, usable_mm))
            elements.append(Spacer(1, 7 * mm))
        elements.append(Paragraph('상세 내역', section_style))
        elements.append(Spacer(1, 2.5 * mm))
        # 사용자 보고("네트워크 상태보고서를 pdf로 받았는데 엉망이야" --
        # IP(예: "192.168.30.250")가 "192.16/8.30.2/50"처럼 글자 단위로
        # 줄바꿈돼 깨져 보임 / "상태 보고서 전부 pdf 상태 확인해서
        # 수정해줘" -- 장애 이력 보고서도 시각("2026-11-08 21:51")과
        # 장비/출처("DESKTOP-938NHR6")가 똑같이 글자 단위로 깨짐):
        # 기존엔 '내용' 컬럼이 있는 보고서(장애 이력)는 그 컬럼에 폭의
        # 절반을 몰아주고 나머지 전부를 똑같이(컬럼 수로 균등) 나눴고,
        # '내용' 컬럼이 없는 보고서(네트워크/자원 사용률)는 0번째
        # 컬럼(장비명)에 몰아주고 나머지를 균등 분배했다. 두 경우 다
        # "나머지"가 컬럼이 많아지면(7개) 턱없이 좁아져서(15mm 안팎)
        # 실제로 긴 값(IP, 날짜+시각, 긴 장비명, 한글이라 넓은 MTTR/MTBF)
        # 이 들어갈 공간이 없어 글자 단위로 깨졌다.
        #
        # 모든 보고서에 공통으로 "각 컬럼의 실제 내용 길이(헤더/모든 행의
        # 최댓값, 한글 등 2배 폭 문자는 가중)에 비례해 폭 배분" 방식을
        # 적용하되, 아무리 짧은 컬럼도 MIN_MM 밑으로는 안 내려가게 바닥을
        # 깔고(그래야 '분류'처럼 원래 아주 짧은 컬럼도 안전 마진이 생김),
        # '내용'처럼 유독 긴 컬럼 하나가 MAX_FRACTION을 넘겨 나머지를
        # 다 잡아먹지 않게 상한도 둔다. 상한을 넘겨 깎인 만큼은 아직 여유가
        # 있는 컬럼들에 비례 배분한다.
        n = len(columns)
        MIN_MM = 15.0
        MAX_FRACTION = 0.42

        def _display_len(s):
            # unicodedata.east_asian_width: 'W'(Wide)/'F'(Fullwidth) 글자
            # (한글 음절 포함)는 라틴 문자/숫자 폭의 약 2배로 계산.
            return sum(2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1 for ch in str(s))

        col_weights = []
        for ci in range(n):
            longest = _display_len(columns[ci])
            for row in rows:
                longest = max(longest, _display_len(row[ci]))
            col_weights.append(max(longest, 3))  # floor so no column collapses to ~0
        total_weight = sum(col_weights)
        widths = [usable_mm * w / total_weight for w in col_weights]

        # 1차: MIN_MM 바닥 적용, 부족분은 이미 MIN_MM 이상인 컬럼들에서
        # 비례적으로 빌려온다.
        deficit = 0.0
        flexible_idx = []
        for i in range(n):
            if widths[i] < MIN_MM:
                deficit += MIN_MM - widths[i]
                widths[i] = MIN_MM
            else:
                flexible_idx.append(i)
        if deficit > 0 and flexible_idx:
            flex_total = sum(widths[i] for i in flexible_idx)
            if flex_total > 0:
                for i in flexible_idx:
                    widths[i] -= deficit * (widths[i] / flex_total)

        # 2차: MAX_FRACTION 상한 적용, 초과분은 상한에 안 걸린 컬럼들에
        # 비례적으로 돌려준다.
        max_mm = usable_mm * MAX_FRACTION
        excess = 0.0
        capped = set()
        for i in range(n):
            if widths[i] > max_mm:
                excess += widths[i] - max_mm
                widths[i] = max_mm
                capped.add(i)
        if excess > 0:
            remaining_idx = [i for i in range(n) if i not in capped]
            remaining_total = sum(widths[i] for i in remaining_idx)
            if remaining_total > 0:
                for i in remaining_idx:
                    widths[i] += excess * (widths[i] / remaining_total)
        # XML 마크업 주입 대응(validation.escape_pdf_text 주석 참고) -- reportlab의
        # Paragraph는 문자열을 그대로 마크업으로 해석하고 자동 이스케이프하지 않는다.
        # 등급(심각도/상태/가동률)이 있는 컬럼은 화면과 같은 색으로 강조
        # (_cell_paragraph) -- 나머지는 기존처럼 일반 텍스트.
        table_data = [columns] + [[_cell_paragraph(report_type, ci, c) for ci, c in enumerate(row)] for row in rows]
        t = Table(table_data, repeatRows=1, colWidths=[w * mm for w in widths])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Korean'),
            ('FONTNAME', (0, 0), (-1, 0), 'KoreanBold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1c2333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#dddddd')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7f8fb')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t)
    doc.build(elements, onFirstPage=_decorate, onLaterPages=_decorate)
    return buf.getvalue()


def build_excel(report_type, start_ms, end_ms, device_id=None, group=None):
    columns, rows = _REPORT_GATHERERS[report_type](start_ms, end_ms, device_id, group)
    title = _REPORT_TITLES[report_type]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = title[:31]  # Excel sheet-name length cap
    ws['A1'] = f'InfraSight {title}'
    ws['A1'].font = Font(bold=True, size=14)
    ws['A2'] = f"기간: {_fmt_ms(start_ms)} ~ {_fmt_ms(end_ms)}"
    ws['A3'] = validation.sanitize_excel_cell(_filter_desc(device_id, group))
    ws['A4'] = f"생성 시각: {_fmt_ms(int(time.time() * 1000))}"
    header_row = 6
    for ci, col in enumerate(columns, start=1):
        cell = ws.cell(row=header_row, column=ci, value=col)
        cell.font = Font(bold=True, color='FFFFFF')
        cell.fill = PatternFill('solid', fgColor='1C2333')
        cell.alignment = Alignment(horizontal='center')
    for ri, row in enumerate(rows, start=header_row + 1):
        for ci, val in enumerate(row, start=1):
            # CSV/Excel Formula Injection(OWASP) 대응 -- validation.
            # sanitize_excel_cell 주석 참고.
            ws.cell(row=ri, column=ci, value=validation.sanitize_excel_cell(val))
    for ci, col in enumerate(columns, start=1):
        max_len = max([len(str(col))] + [len(str(row[ci - 1])) for row in rows]) if rows else len(str(col))
        ws.column_dimensions[get_column_letter(ci)].width = min(max(max_len + 2, 10), 60)
    ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def build_report(report_type, fmt, start_ms, end_ms, device_id=None, group=None):
    if report_type not in _REPORT_GATHERERS:
        raise ValueError('지원하지 않는 보고서 종류입니다')
    title = _REPORT_TITLES[report_type]
    date_tag = time.strftime('%Y%m%d', time.localtime(start_ms / 1000)) + '-' + time.strftime('%Y%m%d', time.localtime(end_ms / 1000))
    if fmt == 'pdf':
        data = build_pdf(report_type, start_ms, end_ms, device_id, group)
        return data, f'InfraSight_{title}_{date_tag}.pdf', 'application/pdf'
    elif fmt == 'excel':
        data = build_excel(report_type, start_ms, end_ms, device_id, group)
        return data, f'InfraSight_{title}_{date_tag}.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    raise ValueError('지원하지 않는 형식입니다 (pdf 또는 excel)')
