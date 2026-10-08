<template>
  <Card class="overflow-hidden" data-testid="opencode-ip-pool-panel">
    <!-- 头部：标题 + 扫描 / 清理 -->
    <div class="p-4 border-b border-border/60">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold">
          {{ legacyT('前置代理池') }}
        </h3>
        <div class="flex flex-wrap items-center justify-end gap-2">
          <!-- 扫描只产出候选，复验才产出生产池：两个按钮分开是因为它们
               代价差一个数量级（扫描 50 分钟/轮，复验 3 分钟/轮）。 -->
          <Button
            variant="outline"
            size="sm"
            class="h-9"
            :disabled="taskBusy"
            @click="handleScan"
          >
            <Loader2 v-if="status?.scanning" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            <ScanSearch v-else class="mr-1.5 h-3.5 w-3.5" />
            {{ status?.scanning ? legacyT('扫描候选中…') : legacyT('扫描候选') }}
          </Button>
          <Button
            variant="outline"
            size="sm"
            class="h-9"
            :disabled="taskBusy"
            @click="handleVerify"
          >
            <Loader2 v-if="verifying" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            <ShieldCheck v-else class="mr-1.5 h-3.5 w-3.5" />
            {{ verifying ? legacyT('复验中…') : legacyT('复验健康') }}
          </Button>
          <Button
            variant="outline"
            size="sm"
            class="h-9"
            :disabled="taskBusy"
            @click="handleClean"
          >
            <Loader2 v-if="status?.cleaning" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
            <Sparkles v-else class="mr-1.5 h-3.5 w-3.5" />
            {{ status?.cleaning ? legacyT('清理中…') : legacyT('清理') }}
          </Button>
        </div>
      </div>

      <!-- 进度独占一行，不挤在按钮中间。
           原来它和三个按钮同处一个 flex 容器，位置夹在「复验健康」和「清理」之间：
           按钮一多就换行错位，进度文字还跟着左右跳，读者很难把「正在复验」和
           它前面的按钮对上。放到按钮行下面单独一行，位置固定，也不会把按钮
           挤到别处去。 -->
      <p
        v-if="progressText"
        class="text-[11px] text-muted-foreground font-mono tabular-nums mt-2"
      >
        {{ progressText }}
      </p>
    </div>

    <!-- 前置代理域名（面板首要配置项） -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 space-y-2 bg-muted/20">
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <Globe class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-sm font-medium shrink-0">{{ legacyT('启用前置代理') }}</span>
          <Switch
            :model-value="proxyEnabled"
            :disabled="busy || savingConfig"
            @update:model-value="handleToggleProxy"
          />
          <Badge variant="secondary" class="font-mono text-[11px] truncate max-w-[220px]">
            {{ proxyEnabled && proxyDomainInput ? proxyDomainInput : status.original_domain || 'opencode.ai' }}
          </Badge>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <Input
          v-model="proxyDomainInput"
          placeholder="cdn.example.com"
          class="h-8 font-mono text-sm"
          :disabled="busy || savingConfig"
          @keydown.enter.prevent="handleSaveConfig"
        />
        <Button
          variant="outline"
          size="sm"
          class="h-8 shrink-0"
          :disabled="busy || savingConfig || !proxyDomainDirty"
          @click="handleSaveConfig"
        >
          <Save v-if="!savingConfig" class="mr-1.5 h-3.5 w-3.5" />
          <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
          {{ legacyT('保存') }}
        </Button>
      </div>
      <p class="text-[11px] text-muted-foreground">
        <template v-if="proxyEnabled && proxyDomainInput">
          {{
            legacyT(
              '开启：本次请求使用上方域名，配合池内 IP 分散每日免费额度。端点仍显示真实上游，不会被改写。',
            )
          }}
        </template>
        <template v-else-if="proxyEnabled">
          {{ legacyT('已开启但未填写域名，本次请求仍使用默认官方地址。') }}
        </template>
        <template v-else>
          {{ legacyT('关闭：本次请求使用默认官方地址。上方填写的域名会保留，随时可重新开启。') }}
        </template>
      </p>
    </div>

    <!-- 扫描配置 -->
    <div class="px-4 py-3 border-b border-border/40 space-y-3">
      <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        {{ legacyT('扫描配置') }}
      </h4>

      <div>
        <label class="text-xs text-muted-foreground block mb-1.5">
          {{ legacyT('扫描网段 (CIDR)') }}
        </label>
        <div class="flex flex-wrap gap-1.5">
          <template v-for="(cidr, idx) in cidrInputs" :key="`${idx}-${cidr}`">
            <Badge variant="secondary" class="gap-1.5 pr-1 text-xs font-mono">
              {{ cidr }}
              <button class="hover:text-destructive transition-colors" @click="removeCidr(idx)">
                <X class="h-3 w-3" />
              </button>
            </Badge>
          </template>
          <span v-if="cidrInputs.length === 0" class="text-xs text-muted-foreground py-1">
            {{ legacyT('暂无网段，请添加') }}
          </span>
        </div>
        <div class="flex items-center gap-2 mt-1.5">
          <Input
            v-model="newCidr"
            class="h-8 font-mono text-sm"
            placeholder="203.0.113.0/24"
            @keydown.enter.prevent="addCidr"
            @blur="addCidr"
          />
          <Button variant="outline" size="sm" class="h-8 shrink-0" :disabled="!newCidr.trim()" @click="addCidr">
            <Plus class="mr-1.5 h-3.5 w-3.5" />
            {{ legacyT('添加') }}
          </Button>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('并发探测数') }}
          </label>
          <Input v-model.number="concurrency" type="number" min="1" max="128" class="h-8" />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('自动扫描间隔 (小时)') }}
          </label>
          <Input
            v-model.number="intervalHours"
            type="number"
            min="0"
            :disabled="!autoEnabled"
            class="h-8"
          />
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('额度冷却 (分钟)') }}
          </label>
          <Input
            v-model.number="cooldownMinutes"
            type="number"
            min="1"
            max="1440"
            class="h-8"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('上次使用的锚点') }}
          </label>
          <div class="h-8 flex items-baseline gap-2">
            <span class="font-mono text-sm text-foreground tabular-nums">
              {{ rotationLastIp || '—' }}
            </span>
            <!-- 显示「第 N / M 个」而不是单调递增的原始游标。
                 游标只是个累计次数，它取模之后落在哪一位才是"实际位置"，
                 直接显示 1237 对排查现场没有任何意义。原始游标移到 title 里，
                 需要时悬停还能看到。
                 游标不参与选取时（轮转关闭 / 会话粘性生效）不显示位置，只留池
                 大小；此时显示位置会和左边那个 IP 对不上号，比不显示更糟。 -->
            <span
              class="font-mono text-xs text-muted-foreground tabular-nums"
              :title="rotationPositionTitle"
            >
              <template v-if="rotationPositionMeaningful && rotationLastIndex >= 0">
                {{ legacyT('第') }} {{ rotationLastIndex + 1 }} / {{ rotationPoolSize }}
              </template>
              <template v-else>
                {{ legacyT('共') }} {{ rotationPoolSize }}
              </template>
            </span>
          </div>
        </div>
      </div>

      <!-- 保存按钮原先在这一行右侧，夹在扫描配置块中间。已移到健康维护块末尾。 -->
      <div class="flex items-center gap-2">
        <Switch v-model="autoEnabled" />
        <span class="text-xs">{{ legacyT('自动扫描') }}</span>
      </div>

      <div class="flex items-center justify-between border-t border-border/40 pt-3">
        <div class="flex items-center gap-2 min-w-0">
          <Repeat2 class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-xs shrink-0">{{ legacyT('轮询规则') }}</span>
          <Switch v-model="rotationEnabled" />
          <Badge variant="secondary" class="text-[10px] h-4 px-1.5 shrink-0">
            {{
              rotationEnabled
                ? legacyT('记住上次出口，下次 +1')
                : legacyT('沿用系统默认调度')
            }}
          </Badge>
        </div>
        <p class="text-[11px] text-muted-foreground text-right">
          {{
            rotationEnabled
              ? legacyT('每次请求在池内 IP 间轮转，各自有独立免费额度')
              : legacyT('关闭时由系统调度策略决定用哪个 IP')
          }}
        </p>
      </div>
      <p v-if="autoEnabled && intervalHours <= 0" class="text-[11px] text-destructive">
        {{ legacyT('自动扫描已开启，但间隔为 0，不会自动执行。') }}
      </p>
      <!-- 池子偏小时提示补池。阈值取 32：低于它，会话粘性的收益已经
           撑不住（一个设备钉住一个节点就占掉 3% 的池），而自动扫描
           默认关闭、间隔以天计，池子只减不增。 -->
      <p v-if="needsMoreCandidates" class="text-[11px] text-amber-600 dark:text-amber-500">
        {{ legacyT('健康节点不足 32 个，建议手工执行一次「扫描候选」补充池子。') }}
      </p>
    </div>

    <!-- 验健康：与扫描分开的一组开关。扫描 50 分钟/轮、复验 3 分钟/轮，
         差一个数量级，放在一起没法各自调。 -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 space-y-3">
      <div class="flex items-center gap-2">
        <ShieldCheck class="h-4 w-4 text-primary" />
        <span class="text-xs font-semibold">{{ legacyT('健康维护') }}</span>
        <Badge variant="secondary" class="text-[10px] h-4 px-1.5">
          {{ legacyT('上次复验') }} {{ formatTimestamp(status?.last_verify_at) }}
        </Badge>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('首字节中位数上限 (毫秒)') }}
          </label>
          <Input
            v-model.number="verifyMaxMedianMs"
            type="number"
            min="1000"
            max="120000"
            step="500"
            class="h-8"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('自动复验间隔 (小时)') }}
          </label>
          <Input
            v-model.number="verifyIntervalHours"
            type="number"
            min="0"
            max="168"
            class="h-8"
          />
        </div>
        <div>
          <label class="text-xs text-muted-foreground block mb-1.5">
            {{ legacyT('保底池大小') }}
          </label>
          <Input v-model.number="minPoolSize" type="number" min="1" max="512" class="h-8" />
        </div>
        <div class="flex items-end pb-1.5">
          <div class="flex items-center gap-2">
            <Switch v-model="autoVerifyEnabled" />
            <span class="text-xs">{{ legacyT('自动复验') }}</span>
          </div>
        </div>
      </div>

      <p class="text-[11px] text-muted-foreground">
        {{
          legacyT('复验把候选按真实负载多采样几次，取中位数判定；每次都达标才进入轮转。')
        }}
      </p>
      <p
        v-if="autoVerifyEnabled && verifyIntervalHours <= 0"
        class="text-[11px] text-destructive"
      >
        {{ legacyT('自动复验已开启，但间隔为 0，不会自动执行。') }}
      </p>

      <!-- 规模自适应：开关与「为什么没生效」一起显示。
           自动降级如果静默生效，使用者无法区分是保护机制还是故障。 -->
      <div class="space-y-2 pt-1">
        <div class="flex items-center gap-2">
          <Switch
            v-model="sessionStickyEnabled"
            :disabled="!sessionStickyActive && sessionStickyEnabled"
          />
          <span class="text-xs">{{ legacyT('会话粘性') }}</span>
          <Badge
            v-if="sessionStickyActive"
            variant="secondary"
            class="text-[10px] h-4 px-1.5"
          >
            {{ legacyT('生效中') }}
          </Badge>
          <Badge
            v-else-if="sessionStickyReason"
            variant="outline"
            class="text-[10px] h-4 px-1.5"
          >
            {{ sessionStickyReason }}
          </Badge>
        </div>
        <p class="text-[11px] text-muted-foreground">
          {{
            legacyT('同一会话全程落在同一节点，延迟可预期；池太小时自动停用。')
          }}
        </p>

        <div class="flex items-center gap-2">
          <Switch v-model="passiveDegradeEnabled" />
          <span class="text-xs">{{ legacyT('被动降权') }}</span>
          <Badge
            v-if="passiveDegradeActive"
            variant="secondary"
            class="text-[10px] h-4 px-1.5"
          >
            {{ legacyT('生效中') }}
          </Badge>
          <Badge
            v-else-if="passiveDegradeReason"
            variant="outline"
            class="text-[10px] h-4 px-1.5"
          >
            {{ passiveDegradeReason }}
          </Badge>
        </div>
        <!-- 被动降权的两个时间：阈值与冷却时长。
             阈值只给下限不给更低：线上 15 万 token 的正常流式请求首字节最长
             12980 ms，调到 10 秒会让这类请求把自己的健康节点判成慢节点，
             降权机制反过来成了故障源。所以 min 就是 15000，只能往上调。 -->
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('首字节阈值 (毫秒)') }}
            </label>
            <Input
              v-model.number="passiveDegradeFirstByteMs"
              type="number"
              :min="DEGRADE_FIRST_BYTE_MS_MIN"
              :max="DEGRADE_FIRST_BYTE_MS_MAX"
              :step="1000"
              class="h-8"
            />
            <p class="text-[11px] text-muted-foreground mt-1">
              {{ legacyT(`真实请求首字节超过此值即降权；下限 15000 毫秒，实测正常大请求最长约 13000 毫秒。`) }}
            </p>
          </div>
          <div>
            <label class="text-xs text-muted-foreground block mb-1.5">
              {{ legacyT('降权冷却 (分钟)') }}
            </label>
            <Input
              v-model.number="passiveDegradeCooldownMinutes"
              type="number"
              :min="1"
              :max="1440"
              class="h-8"
            />
            <p class="text-[11px] text-muted-foreground mt-1">
              {{ legacyT('被降权的节点在此期间不参与轮转，结束后自动回来重新证明自己。') }}
            </p>
          </div>
        </div>
        <p class="text-[11px] text-muted-foreground">
          {{
            legacyT('真实请求若成功但首字节超阈值，该节点进短冷却，不必等下一轮复验。')
          }}
        </p>
      </div>

      <!-- 保存按钮放在**所有**可改字段之后，而不是夹在扫描配置块中间。
           它管的是整卡设置（网段、扫描、轮询、健康维护、被动降权），而健康维护
           整块都在按钮下方：用户改完最下面的开关要往上翻才找得到，找不到就
           以为开关没生效——其实只是没保存，于是又拨一次，看着像"自动弹回关闭"。
           有未保存改动时给出提示，把"没保存"这件事说出来。 -->
      <div class="flex items-center gap-2 pt-1">
        <span
          v-if="configDirty"
          class="text-[11px] text-amber-600 dark:text-amber-500"
        >
          {{ legacyT('有未保存的修改') }}
        </span>
        <Button
          variant="outline"
          size="sm"
          class="h-8 shrink-0 ml-auto"
          :disabled="busy || savingConfig || !configDirty"
          @click="handleSaveConfig"
        >
          <Save v-if="!savingConfig" class="mr-1.5 h-3.5 w-3.5" />
          <Loader2 v-else class="mr-1.5 h-3.5 w-3.5 animate-spin" />
          {{ legacyT('保存配置') }}
        </Button>
      </div>
    </div>

    <!-- 分层状态条：候选 → 健康 → 在用。
         只有这三个数放在一起，才看得出扫描到底筛掉了什么。 -->
    <div class="px-4 py-3 border-b border-border/40">
      <div class="flex items-center gap-2 flex-wrap text-xs">
        <span class="text-muted-foreground">{{ legacyT('候选') }}</span>
        <span class="font-mono tabular-nums">{{ candidateCount }}</span>
        <span class="text-muted-foreground/50">→</span>
        <span class="text-muted-foreground">{{ legacyT('健康') }}</span>
        <span class="font-mono tabular-nums text-primary">{{ healthyCount }}</span>
        <span class="text-muted-foreground/50">→</span>
        <span class="text-muted-foreground">{{ legacyT('在用') }}</span>
        <span class="font-mono tabular-nums">{{ inUseCount }}</span>
        <Badge
          v-if="degradedCount > 0"
          variant="outline"
          class="text-[10px] h-4 px-1.5"
        >
          {{ legacyT('降级') }} {{ degradedCount }}
        </Badge>
      </div>
      <p v-if="poolEmpty" class="mt-1.5 text-[11px] text-muted-foreground">
        {{
          legacyT(
            '当前为直连代理模式：不做 CDN 锚定，延迟通常更低，但失去配额分散。'
          )
        }}
      </p>
      <p
        v-else-if="lastVerifyDropped > 0"
        class="mt-1.5 text-[11px] text-muted-foreground"
      >
        {{
          legacyT('上次复验淘汰')
        }}
        {{ lastVerifyDropped }} {{ legacyT('个（延迟超标或超时）') }}
      </p>
    </div>

    <!-- 最近运行统计 -->
    <div class="px-4 py-3 border-b border-border/40 grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次扫描') }}</span>
        <span class="font-mono">{{ formatTimestamp(status?.last_scan_at) }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('上次清理') }}</span>
        <span class="font-mono">{{ formatTimestamp(status?.last_clean_at) }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('探测目标') }}</span>
        <span class="font-mono">{{ status?.last_scan_targets ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('清理检查') }}</span>
        <span class="font-mono">{{ status?.last_clean_checked ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('新增 IP') }}</span>
        <span class="font-mono text-primary">{{ status?.last_scan_added ?? 0 }}</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted-foreground">{{ legacyT('移除 IP') }}</span>
        <span class="font-mono text-destructive">{{ status?.last_clean_removed ?? 0 }}</span>
      </div>
    </div>

    <!-- 节点明细：按可信度分三组。
         分组本身就是信息——「已淘汰」这一栏在出事时最有用：
         它直接回答了「池里那些慢节点是怎么进来的、又被谁拦下的」。 -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40">
      <!-- 标签栏不再自带 border-b：它下面紧跟着列头也有一条，两条线只隔几像素
           叠在一起，看起来像糊成一片，列头也就贴着上面那排统计读不出来。
           选中标签的 border-b-2 已经足够表明当前选中哪一组。 -->
      <div class="flex items-center gap-1 mb-3">
        <button
          v-for="tab in poolTabs"
          :key="tab.key"
          type="button"
          class="px-2.5 py-1.5 text-xs border-b-2 -mb-px transition-colors"
          :class="
            poolTab === tab.key
              ? 'border-primary text-foreground font-medium'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          "
          @click="poolTab = tab.key"
        >
          {{ tab.label }}
          <span class="font-mono tabular-nums ml-1 text-[10px]">{{ tab.count }}</span>
        </button>
      </div>

      <!-- 列头与三组列表共用同一套网格 8rem / 5.5rem / 1fr：IP 固定宽度左对齐，
           延迟固定宽度居中，剩下的宽度全给状态标记并居中。
           IP 列取 8rem 是按最长的 IPv4（15 字符）等宽字形留的余量：再宽就只是
           把大片空白留在左边，看起来像内容被推到中间；超长会 truncate 而不是换行
           把行高撑开。表头和数据用同一套网格 + 同一套对齐方式，所以不会各说各话。
           标记列用 justify-center 而不是 text-center：徽章容器是 flex，
           text-align 对 flex 子元素不生效，必须同时改 justify。

           第三列表头按当前标签页给不同名字：它在「在用」里是行内徽章（降级/
           保护/已停用），在「已淘汰」里是淘汰原因，在「候选」里根本不存在
           （272 条一条徽章都没有）。统一叫「状态」是错的——那三样不是同一个
           维度；候选那栏干脆留空，空白表头表示这一列当前没有内容。 -->
      <div class="max-h-64 overflow-y-auto">
        <!-- 粘性表头：列头和数据行必须在同一个滚动容器里。
             之前列头在容器外、数据行在 max-h-56 overflow-y-auto 里，在用 65 行、
             候选 272 行必然出纵向滚动条，滚动条把行的可用宽度挤窄约 15px 而列头
             不受影响，右侧那列就相对表头整体偏左。共用容器后两边内容盒完全
             相同，不会错位；做成 sticky 后滚动时表头也始终可见。 -->
        <div
          class="sticky top-0 z-10 bg-card grid grid-cols-[8rem_5.5rem_1fr] items-center gap-2 py-1.5 border-b border-border/40 text-[10px] uppercase tracking-wide text-muted-foreground/70"
        >
          <span class="truncate">{{ legacyT('IP') }}</span>
          <span class="text-center">{{ legacyT('延迟') }}</span>
          <span class="text-center truncate">{{ poolStatusHeader }}</span>
        </div>

      <!-- 在用 -->
      <div v-if="poolTab === 'in_use'" class="text-xs">
        <p v-if="inUseRows.length === 0" class="text-muted-foreground py-2">
          {{ legacyT('没有可用节点：当前为直连代理模式，不做 CDN 锚定。') }}
        </p>
        <div v-else>
          <div
            v-for="row in inUseRows"
            :key="row.ip"
            class="grid grid-cols-[8rem_5.5rem_1fr] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="font-mono truncate">{{ row.ip }}</span>
            <span
              class="font-mono tabular-nums text-center"
              :class="row.latencyMs > verifyMaxMedianMs * 0.7 ? 'text-amber-600' : 'text-muted-foreground'"
            >
              {{ row.latencyText }}
            </span>
            <span class="flex items-center gap-2 justify-center">
              <Badge v-if="row.degraded" variant="outline" class="text-[10px] h-4 px-1.5">
                {{ legacyT('降级') }}
              </Badge>
              <Badge v-if="row.pinned" variant="secondary" class="text-[10px] h-4 px-1.5">
                {{ legacyT('保护') }}
              </Badge>
              <Badge v-if="row.disabled" variant="outline" class="text-[10px] h-4 px-1.5">
                {{ legacyT('已停用') }}
              </Badge>
            </span>
          </div>
        </div>
      </div>

      <!-- 候选：还没被信任，但值得记住 -->
      <div v-else-if="poolTab === 'candidate'" class="text-xs">
        <p v-if="candidateRows.length === 0" class="text-muted-foreground py-2">
          {{ legacyT('候选池为空。执行一次扫描以收集候选节点。') }}
        </p>
        <div v-else>
          <div
            v-for="row in candidateRows"
            :key="row.ip"
            class="grid grid-cols-[8rem_5.5rem_1fr] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="font-mono text-muted-foreground truncate">{{ row.ip }}</span>
            <span class="font-mono tabular-nums text-center text-muted-foreground">
              {{ row.latencyText }}
            </span>
            <span />
          </div>
        </div>
      </div>

      <!-- 已淘汰：体检报告 -->
      <div v-else class="text-xs">
        <p v-if="rejectionRows.length === 0" class="text-muted-foreground py-2">
          {{ legacyT('上轮没有节点被淘汰。') }}
        </p>
        <div v-else>
          <div
            v-for="row in rejectionRows"
            :key="row.ip"
            class="grid grid-cols-[8rem_5.5rem_1fr] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="font-mono text-muted-foreground truncate">{{ row.ip }}</span>
            <span class="font-mono tabular-nums text-center text-muted-foreground">
              {{ row.latencyText }}
            </span>
            <span class="flex items-center gap-2 justify-center">
              <Badge variant="outline" class="text-[10px] h-4 px-1.5">
                {{ row.reasonText }}
              </Badge>
            </span>
          </div>
        </div>
      </div>
      </div>
    </div>

    <!-- 池内 IP -->
    <div class="px-4 py-3">
      <h4 class="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
        {{ legacyT('池内 IP') }} ({{ poolIps.length }})
      </h4>

      <div class="flex items-center gap-2 mb-2">
        <Input
          v-model="newIpInput"
          class="h-8 font-mono text-sm"
          placeholder="203.0.113.118"
          @keydown.enter.prevent="handleAddIp"
        />
        <Button
          variant="outline"
          size="sm"
          class="h-8 shrink-0"
          :disabled="busy || !newIpInput.trim()"
          @click="handleAddIp"
        >
          <Plus class="mr-1.5 h-3.5 w-3.5" />
          {{ legacyT('手动添加 IP') }}
        </Button>
      </div>
      <p class="text-[11px] text-muted-foreground mb-2">
        {{
          legacyT(
            '每个 IP 对应一个密钥，出口 IP 记录在密钥的 upstream_metadata.opencode_exit_ip，不占用 API Key 字段。',
          )
        }}
      </p>

      <div v-if="poolIps.length === 0" class="py-6 text-center">
        <Network class="w-10 h-10 mx-auto mb-2 opacity-40" />
        <p class="text-sm text-muted-foreground">
          {{ legacyT('暂无池内 IP，点击"扫描"从配置网段中发现可用出口 IP，或在上方手动添加。') }}
        </p>
      </div>
      <div
        v-else
        class="divide-y divide-border/40 rounded-md border border-border/50 overflow-hidden"
      >
        <div
          v-for="ip in pagedIps"
          :key="ip.ip"
          class="px-3 py-2 flex items-center justify-between gap-2 hover:bg-muted/30"
        >
          <div class="flex items-center gap-2 min-w-0">
            <span
              class="inline-flex h-2 w-2 rounded-full shrink-0"
              :class="ip.is_active ? 'bg-emerald-500' : 'bg-red-400'"
            />
            <template v-if="editingRowIp === ip.ip">
              <Input
                v-model="editingIp"
                class="h-7 w-40 font-mono text-sm"
                @keydown.enter.prevent="commitEditIp(ip)"
                @keydown.esc="editingRowIp = null"
              />
              <Button variant="ghost" size="sm" class="h-7 px-2" :disabled="busy" @click="commitEditIp(ip)">
                <Check class="h-3.5 w-3.5" />
              </Button>
              <Button variant="ghost" size="sm" class="h-7 px-2" @click="editingRowIp = null">
                <X class="h-3.5 w-3.5" />
              </Button>
            </template>
            <span v-else class="text-sm font-mono truncate">{{ ip.ip }}</span>
            <span v-if="!ip.is_active" class="text-xs text-muted-foreground shrink-0">
              {{ legacyT('未启用') }}
            </span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground"
              :disabled="busy"
              :title="ip.is_active ? legacyT('停用') : legacyT('启用')"
              @click="handleToggleIp(ip)"
            >
              <Power class="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground"
              :disabled="busy"
              :title="legacyT('修改 IP')"
              @click="startEditIp(ip)"
            >
              <Pencil class="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              class="h-7 px-2 text-muted-foreground hover:text-destructive"
              :disabled="busy"
              :title="legacyT('删除')"
              @click="handleDeleteIp(ip)"
            >
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
      <Pagination
        v-if="poolIps.length > 0"
        :current="ipPage"
        :total="poolIps.length"
        :page-size="ipPageSize"
        :page-size-options="[50, 100, 200]"
        :show-page-size-selector="false"
        :cache-key="`opencode-ip-pool-page-size-${props.provider.id}`"
        @update:current="ipPage = $event"
        @update:page-size="ipPageSize = $event"
      />
    </div>

    <!-- 错误提示 -->
    <div
      v-if="errorMessage"
      class="px-4 py-2.5 bg-destructive/10 text-destructive text-xs border-t border-destructive/20"
    >
      {{ errorMessage }}
    </div>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import Badge from '@/components/ui/badge.vue'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Pagination from '@/components/ui/pagination.vue'
import Switch from '@/components/ui/switch.vue'
import {
  Check,
  Globe,
  Loader2,
  Network,
  Pencil,
  Plus,
  Power,
  Repeat2,
  RotateCcw,
  Save,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from 'lucide-vue-next'
import { useI18n } from '@/i18n'
import {
  addOpenCodeExitIp,
  addProviderKey,
  deleteEndpointKey,
  removeOpenCodeExitIp,
  getOpenCodeIpPoolStatus,
  restoreOpenCodeOriginalBaseUrl,
  runOpenCodeIpPoolClean,
  runOpenCodeIpPoolScan,
  runOpenCodeIpPoolVerify,
  saveOpenCodeIpPoolConfig,
  updateProviderKey,
  updateOpenCodeExitIp,
  toggleOpenCodeExitIp,
  type OpenCodeIpPoolStatus,
} from '@/api/endpoints'
import type { ProviderWithEndpointsSummary } from '@/api/endpoints/types'
import { getErrorMessage } from '@/types/api-error'

const props = defineProps<{
  provider: ProviderWithEndpointsSummary
}>()

const emit = defineEmits<{
  refresh: []
}>()

const { legacyT } = useI18n()

interface PoolIpRow {
  key_id: string
  ip: string
  is_active: boolean
}

const status = ref<OpenCodeIpPoolStatus | null>(null)
/**
 * 被动降权阈值的上下限，与后端校验保持一致。
 *
 * 下限 15000 不是随手取的：线上 15 万 token 的正常流式请求首字节最长
 * 12980 ms，阈值低于这个值会让正常的大请求把自己的健康节点判成慢节点。
 * 后端同样强制这个下限（validate_section 与取值器两处），三边必须一致。
 */
const DEGRADE_FIRST_BYTE_MS_MIN = 15000
const DEGRADE_FIRST_BYTE_MS_MAX = 120000
/**
 * 上一次从服务端拿到的状态，用来判断某个字段有没有被用户改过。
 * 见 keepUserEdit：本地值不再等于这里的值，就说明用户正在编辑它。
 */
const lastServerStatus = ref<OpenCodeIpPoolStatus | null>(null)
const cidrInputs = ref<string[]>([])
const newCidr = ref('')
const concurrency = ref<number>(32)
const intervalHours = ref<number>(0)
const rotationEnabled = ref(false)
const cooldownMinutes = ref<number>(60)
const rotationCursor = ref<number>(0)
const rotationPoolSize = ref<number>(0)
const rotationLastIp = ref<string>('')

/**
 * 上次实际命中的位置（从 0 起；-1 表示暂时算不出来）。
 *
 * 这里**不能**用 rotation_cursor % rotation_pool_size 去算位置：请求路径里的
 * 取模基数是「可用」池，即 exit_pool 剔除手工停用和冷却中的节点
 * （见 opencode_rotation::pick_opencode_exit_ip 里的 usable），而
 * rotation_pool_size 是 effective_pool 的长度，没做这层剔除。只要有一个节点
 * 被停用或在冷却中，两个基数就不相等，取模算出来的是一个看起来很合理、
 * 实际指错节点的位置——比显示原始游标更糟，因为它看着像对的。
 *
 * rotation_last_ip 是请求路径记下的精确值（后端注释也说明了这点：只拿
 * exit_pool 长度去除会偏），它在池里的下标就是真实位置，直接查即可。
 */
const rotationLastIndex = computed(() => {
  const ip = rotationLastIp.value.trim()
  if (!ip) return -1
  const pool = status.value?.exit_pool ?? []
  return pool.findIndex((item) => item.trim() === ip)
})

/**
 * 游标位置当前是否可信，也就是"游标是不是真的决定了这次选中的那个节点"。
 *
 * 两种情况下不该显示位置：
 * - 轮转关闭：游标根本不会被推进，显示位置等于编一个数出来；
 * - 会话粘性生效：锚点由会话哈希决定（opencode_rotation::pick_session_anchor），
 *   游标不推进，旁边那个 IP 也不是游标选出来的。给它配一个位置，读者必然会
 *   以为位置和 IP 是对应的，而实际上两者来自完全不同的选取路径。
 *
 * 这里用后端给的 rotation_effective / session_sticky_active，而不是原始开关：
 * 会话粘性有最小池阈值，池太小时会自动停用，那时开关是开的但实际并未生效，
 * 按开关判断会把一个早已不参与选取的机制当成还在起作用。
 */
// 分层：候选 / 健康 / 在用。三个数放一起才看得出扫描筛掉了什么。
const candidateCount = ref<number>(0)
const healthyCount = ref<number>(0)
const inUseCount = ref<number>(0)
const degradedCount = ref<number>(0)
const lastVerifyDropped = ref<number>(0)
const poolEmpty = ref<boolean>(false)
// 验健康（与扫描分开的两套状态与开关）
const verifying = ref<boolean>(false)
const verifyRunning = ref<boolean>(false)
const autoVerifyEnabled = ref(false)
const verifyIntervalHours = ref<number>(0)
const verifyMaxMedianMs = ref<number>(10000)
const minPoolSize = ref<number>(5)
// 规模自适应：开关与「为什么没生效」一起显示
const sessionStickyEnabled = ref(false)
const sessionStickyActive = ref(false)
const sessionStickyReason = ref<string | null>(null)

// 放在 sessionStickyActive 之后声明：虽然 computed 的 getter 是惰性的、运行时
// 一定能等到初始化，但依赖写在声明前面会让人误以为存在暂时性死区问题。
const rotationPositionMeaningful = computed(() => {
  if (!(status.value?.rotation_effective ?? false)) return false
  return !sessionStickyActive.value
})

const rotationPositionTitle = computed(() => {
  if (rotationPositionMeaningful.value) {
    return `${legacyT('累计轮转次数')} #${rotationCursor.value}`
  }
  if (sessionStickyActive.value) {
    return legacyT('会话粘性生效中：锚点由会话决定，游标不推进')
  }
  return legacyT('轮转已关闭：节点由系统调度决定，没有游标位置')
})
const passiveDegradeEnabled = ref(false)
const passiveDegradeActive = ref(false)
const passiveDegradeReason = ref<string | null>(null)
const passiveDegradeFirstByteMs = ref(DEGRADE_FIRST_BYTE_MS_MIN)
const passiveDegradeCooldownMinutes = ref(15)

type PoolTabKey = 'in_use' | 'candidate' | 'rejected'
const poolTab = ref<PoolTabKey>('in_use')

interface PoolNodeRow {
  ip: string
  latencyMs: number
  latencyText: string
  degraded: boolean
  pinned: boolean
  disabled: boolean
}

function formatLatency(ms?: number | null): string {
  if (ms == null) return '—'
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms}ms`
}

function isPinned(ip: string): boolean {
  return (status.value?.pinned || []).includes(ip)
}

function isDisabled(ip: string): boolean {
  return (status.value?.exit_pool_disabled || []).includes(ip)
}

/** 在用：当前参与轮转的节点，带实测延迟与状态标记。 */
const inUseRows = computed<PoolNodeRow[]>(() =>
  (status.value?.healthy || status.value?.exit_pool || []).map((ip) => {
    const latencyMs = status.value?.latencies?.[ip] ?? Number.POSITIVE_INFINITY
    return {
      ip,
      latencyMs,
      latencyText: formatLatency(status.value?.latencies?.[ip]),
      degraded: (status.value?.degraded || []).includes(ip),
      pinned: isPinned(ip),
      disabled: isDisabled(ip),
    }
  }),
)

/** 候选：进过池但本轮没进 healthy 的，还没被信任。 */
const candidateRows = computed(() =>
  (status.value?.candidates || [])
    .filter((ip) => !(status.value?.healthy || []).includes(ip))
    .map((ip) => ({
      ip,
      latencyText: formatLatency(status.value?.latencies?.[ip]),
    })),
)

/** 已淘汰：上轮被拦下的节点，以及拦下的原因。 */
const rejectionRows = computed(() =>
  Object.entries(status.value?.rejections || {}).map(([ip, detail]) => ({
    ip,
    latencyText: formatLatency(detail.median_ms),
    reasonText:
      detail.reason === 'unreachable'
        ? legacyT('无响应')
        : detail.reason === 'partial_timeout'
          ? legacyT('部分超时')
          : legacyT('延迟超标'),
  })),
)

const poolTabs = computed(() => [
  { key: 'in_use' as const, label: legacyT('在用'), count: inUseRows.value.length },
  { key: 'candidate' as const, label: legacyT('候选'), count: candidateRows.value.length },
  { key: 'rejected' as const, label: legacyT('已淘汰'), count: rejectionRows.value.length },
])

/**
 * 第三列表头。同一列在三组列表里装的是不同的东西：
 * 「在用」是行内徽章（降级/保护/已停用），「已淘汰」是淘汰原因，
 * 「候选」一个都没有。统一写「状态」是把三个不同维度混为一谈；
 * 按当前标签页给对应的名字，候选那栏留空——空白表头表示这一列当前没有内容。
 */
const poolStatusHeader = computed(() => {
  if (poolTab.value === 'in_use') return legacyT('标记')
  if (poolTab.value === 'rejected') return legacyT('原因')
  return ''
})

const autoEnabled = ref(false)
const savingConfig = ref(false)
const busy = ref(false)

/** 健康节点低于此值就提示补池。 */
const LOW_POOL_HINT_THRESHOLD = 32

/**
 * 是否该提示补池。
 *
 * 池子为空时**不提示**：空池是「走域名直连代理」这一合法模式，实测
 * 150K 下 4552ms，是整个调查里最稳的结果。把它报成待修复的问题，
 * 会诱导使用者去填补一个他们并不需要填的洞。
 */
const needsMoreCandidates = computed(() => {
  if (!status.value || poolEmpty.value) return false
  const healthy = status.value.healthy_count ?? 0
  return healthy > 0 && healthy < LOW_POOL_HINT_THRESHOLD
})

/** 组件卸载后停止长任务轮询，避免往已销毁的组件写状态。 */
const unmounted = ref(false)
/** 后台长任务在跑：按钮不再被占住，只改文案 */
const scanRunning = ref(false)
const cleanRunning = ref(false)
const errorMessage = ref<string | null>(null)
const proxyDomainInput = ref('')
const newIpInput = ref('')
/** 正在编辑的池条目（用 IP 标识：provider 级池里没有 key，key_id 全为空） */
const editingRowIp = ref<string | null>(null)
const editingIp = ref('')
const domainSyncHint = ref('')

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * 时间戳只显示到秒。
 * 后端返回的是 RFC3339 纳秒精度，例如
 * `2026-09-26T15:49:50.682213785+00:00`，直接展示既占地方又读不出来。
 */
function formatTimestamp(value?: string | null): string {
  if (!value) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    // 解析不了就退化成按空格截断，至少去掉纳秒部分
    return value.replace(/\.\d+/, '').replace('T', ' ').replace('Z', '').replace('+00:00', '')
  }
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ` +
    `${pad(parsed.getHours())}:${pad(parsed.getMinutes())}:${pad(parsed.getSeconds())}`
  )
}

function normalizeIp(raw: string): string | null {
  const value = raw.trim()
  const match = IPV4_PATTERN.exec(value)
  if (!match) return null
  const octets = match.slice(1).map((part) => Number(part))
  if (octets.some((octet) => octet < 0 || octet > 255)) return null
  if (octets[0] === 10 || octets[0] === 127) return null
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return null
  if (octets[0] === 192 && octets[1] === 168) return null
  if (octets[0] === 169 && octets[1] === 254) return null
  if (octets[0] >= 224) return null
  return octets.join('.')
}

const proxyDomainDirty = computed(() => {
  const next = proxyDomainInput.value.trim().toLowerCase()
  const current = (status.value?.proxy_domain || '').trim().toLowerCase()
  return next !== current
})

const isOriginalDomain = computed(() => {
  const proxy = (status.value?.proxy_domain || '').toLowerCase().trim()
  const original = (status.value?.original_domain || '').toLowerCase().trim()
  return original !== '' && proxy === original
})

/**
 * 前置代理开关状态。
 *
 * 独立于端点主机：端点 base_url 始终是真实上游，不会被开关改写。
 * 开关只决定「本次请求用输入框里的域名」还是「用默认官方域名」，
 * 而且**不会改写输入框**——输入框里的域名只归用户所有。
 */
const proxyEnabled = ref(false)

const ORIGINAL_DOMAIN_FALLBACK = 'opencode.ai'

const poolIps = computed<PoolIpRow[]>(() => {
  const rows: PoolIpRow[] = []
  for (const row of status.value?.pool_ips || []) {
    // provider 级池里没有 key（IP 不再挂在密钥上），只有 ip 才是必需项。
    if (!row?.ip) continue
    rows.push({ key_id: row.key_id || '', ip: row.ip, is_active: row.is_active !== false })
  }
  return rows
})

const ipPage = ref(1)
const ipPageSize = ref(50)
const pagedIps = computed<PoolIpRow[]>(() => {
  const start = (ipPage.value - 1) * ipPageSize.value
  return poolIps.value.slice(start, start + ipPageSize.value)
})

const configDirty = computed(
  () =>
    JSON.stringify([...cidrInputs.value].sort()) !==
      JSON.stringify([...(status.value?.cidrs || [])].sort()) ||
    concurrency.value !== (status.value?.concurrency ?? 32) ||
    autoEnabled.value !== (status.value?.auto_enabled ?? false) ||
    intervalHours.value !== (status.value?.interval_hours ?? 0) ||
    rotationEnabled.value !== (status.value?.rotation_enabled ?? false) ||
    Math.max(1, Number(cooldownMinutes.value) || 60) !== (status.value?.cooldown_minutes ?? 60) ||
    // 验健康开关也在同一个「保存配置」按钮里，脏检查必须一并覆盖，
    // 否则改了阈值按钮不亮，用户会以为没生效。
    autoVerifyEnabled.value !== (status.value?.auto_verify_enabled ?? false) ||
    verifyIntervalHours.value !== (status.value?.verify_interval_hours ?? 0) ||
    Math.max(1000, Number(verifyMaxMedianMs.value) || 10000) !==
      (status.value?.verify_max_median_ms ?? 10000) ||
    Math.max(1, Number(minPoolSize.value) || 5) !== (status.value?.min_pool_size ?? 5) ||
    sessionStickyEnabled.value !== (status.value?.session_sticky_enabled ?? false) ||
    passiveDegradeEnabled.value !== (status.value?.passive_degrade_enabled ?? false) ||
    // 降权的两个时间也归脏检查管：漏掉的话用户改了阈值、保存按钮不亮，
    // 看起来就像这两个输入框改了没用。
    clampDegradeFirstByteMs(passiveDegradeFirstByteMs.value) !==
      clampDegradeFirstByteMs(status.value?.passive_degrade_first_byte_ms) ||
    Math.trunc(passiveDegradeCooldownMinutes.value || 15) !==
      (status.value?.passive_degrade_cooldown_minutes ?? 15),
)

function addCidr() {
  const value = newCidr.value.trim()
  if (!value) return
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(value)) {
    errorMessage.value = legacyT(`无效 CIDR：${value}`)
    return
  }
  if (!cidrInputs.value.includes(value)) {
    cidrInputs.value.push(value)
  }
  newCidr.value = ''
  errorMessage.value = null
}

function removeCidr(index: number) {
  cidrInputs.value.splice(index, 1)
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((item, index) => item === b[index])
}

function clampDegradeFirstByteMs(value?: number): number {
  if (value == null || !Number.isFinite(value)) return DEGRADE_FIRST_BYTE_MS_MIN
  return Math.min(DEGRADE_FIRST_BYTE_MS_MAX, Math.max(DEGRADE_FIRST_BYTE_MS_MIN, Math.trunc(value)))
}

/**
 * 用户改过、但还没保存的字段，不能被一次后台刷新静默丢掉。
 *
 * 判据不是「服务端哪个字段变了」，而是「本地值是否还等于上次拿到的服务端值」：
 * 相等说明用户没动过，可以放心用新值覆盖；不等就是他正在编辑，必须留着。
 * 面板里任何别的操作（扫描、复验、增删 IP、切换前置代理）结束都会走到
 * loadStatus，改之前每次都会把没保存的改动抹掉——用户看到的是「我明明拨了，
 * 开关又弹回去了」，然后以为功能坏了。
 *
 * 保存成功后的下一次刷新会自动恢复同步：那时本地值已经等于新的服务端值，
 * 比较自然又会相等。这个判据因此不需要额外的「已编辑」标记，也不会忘记复位。
 */
function keepUserEdit<T>(localValue: T, previousServerValue: T | undefined, nextServerValue: T): T {
  if (previousServerValue === undefined) return nextServerValue
  return localValue === previousServerValue ? nextServerValue : localValue
}

async function loadStatus() {
  try {
    const next = await getOpenCodeIpPoolStatus(props.provider.id)
    const previous = lastServerStatus.value
    status.value = next

    // 网段是列表，逐项比较。
    // 哨兵是 null 而不是 undefined：lastServerStatus 的初值是 null，
    // 第一次加载时还没有"上次的服务端值"可比，此时应当直接采用服务端值。
    const nextCidrs = [...(next.cidrs || [])]
    if (previous === null || sameList(cidrInputs.value, previous.cidrs || [])) {
      cidrInputs.value = nextCidrs
    }
    concurrency.value = keepUserEdit(concurrency.value, previous?.concurrency ?? 32, next.concurrency ?? 32)
    autoEnabled.value = keepUserEdit(autoEnabled.value, previous?.auto_enabled ?? false, next.auto_enabled ?? false)
    intervalHours.value = keepUserEdit(intervalHours.value, previous?.interval_hours ?? 0, next.interval_hours ?? 0)
    rotationEnabled.value = keepUserEdit(rotationEnabled.value, previous?.rotation_enabled ?? false, next.rotation_enabled ?? false)
    cooldownMinutes.value = keepUserEdit(cooldownMinutes.value, previous?.cooldown_minutes ?? 60, next.cooldown_minutes ?? 60)
    autoVerifyEnabled.value = keepUserEdit(autoVerifyEnabled.value, previous?.auto_verify_enabled ?? false, next.auto_verify_enabled ?? false)
    verifyIntervalHours.value = keepUserEdit(verifyIntervalHours.value, previous?.verify_interval_hours ?? 0, next.verify_interval_hours ?? 0)
    verifyMaxMedianMs.value = keepUserEdit(verifyMaxMedianMs.value, previous?.verify_max_median_ms ?? 10000, next.verify_max_median_ms ?? 10000)
    minPoolSize.value = keepUserEdit(minPoolSize.value, previous?.min_pool_size ?? 5, next.min_pool_size ?? 5)
    sessionStickyEnabled.value = keepUserEdit(sessionStickyEnabled.value, previous?.session_sticky_enabled ?? false, next.session_sticky_enabled ?? false)
    passiveDegradeEnabled.value = keepUserEdit(passiveDegradeEnabled.value, previous?.passive_degrade_enabled ?? false, next.passive_degrade_enabled ?? false)
    // 阈值/冷却后端给的是生效值，前端夹一下区间，避免旧数据或手工改库留下的
    // 越界值把输入框卡在一个后端会拒绝的数上。
    passiveDegradeFirstByteMs.value = keepUserEdit(
      passiveDegradeFirstByteMs.value,
      previous?.passive_degrade_first_byte_ms ?? DEGRADE_FIRST_BYTE_MS_MIN,
      clampDegradeFirstByteMs(next.passive_degrade_first_byte_ms),
    )
    passiveDegradeCooldownMinutes.value = keepUserEdit(
      passiveDegradeCooldownMinutes.value,
      previous?.passive_degrade_cooldown_minutes ?? 15,
      Math.min(1440, Math.max(1, Math.trunc(next.passive_degrade_cooldown_minutes ?? 15))),
    )

    // 下面这些是纯展示，用户改不了，一律以服务端为准。
    rotationCursor.value = next.rotation_cursor ?? 0
    rotationPoolSize.value = next.rotation_pool_size ?? (next.exit_pool || []).length
    rotationLastIp.value = next.rotation_last_ip ?? ''
    candidateCount.value = next.candidate_count ?? (next.candidates || []).length
    healthyCount.value = next.healthy_count ?? (next.healthy || []).length
    inUseCount.value = next.in_use_count ?? 0
    degradedCount.value = next.degraded_count ?? (next.degraded || []).length
    lastVerifyDropped.value = next.last_verify_dropped ?? 0
    poolEmpty.value = next.pool_empty ?? false
    verifying.value = next.verifying ?? false
    verifyRunning.value = next.verifying ?? false
    sessionStickyActive.value = next.session_sticky_active ?? false
    sessionStickyReason.value = next.session_sticky_disabled_reason ?? null
    passiveDegradeActive.value = next.passive_degrade_active ?? false
    passiveDegradeReason.value = next.passive_degrade_disabled_reason ?? null
    proxyEnabled.value = next.proxy_enabled ?? false
    // 输入框只做「首次预填」：已有内容（包括用户刚输入但没保存的）一律不动，
    // 开关也不参与写入。域名只归用户所有。
    if (!proxyDomainInput.value.trim()) {
      proxyDomainInput.value = next.saved_proxy_domain || ''
    }
    lastServerStatus.value = next
    const totalPages = Math.max(1, Math.ceil((next.pool_ips?.length ?? 0) / ipPageSize.value))
    if (ipPage.value > totalPages) {
      ipPage.value = totalPages
    }
    errorMessage.value = null
  } catch (err) {
    errorMessage.value = legacyT(`加载前置代理池状态失败：${err}`)
  }
}

async function handleSaveConfig() {
  savingConfig.value = true
  errorMessage.value = null
  try {
    // 先把输入框里还没提交的网段补进去：否则用户「敲了网段直接点保存」时，
    // 那段文字会被静默丢弃，刷新后看起来就像配置回滚了。
    if (newCidr.value.trim()) {
      addCidr()
    }
    const body: Record<string, unknown> = {
      cidrs: cidrInputs.value,
      auto_enabled: autoEnabled.value,
      interval_hours: intervalHours.value,
      concurrency: concurrency.value,
      rotation_enabled: rotationEnabled.value,
      cooldown_minutes: Math.max(1, Number(cooldownMinutes.value) || 60),
      proxy_enabled: proxyEnabled.value,
      // 验健康是独立的一段，不能塞进 opencode_scan —— 后者会把它当成未知字段丢掉。
      opencode_health: {
        auto_verify_enabled: autoVerifyEnabled.value,
        verify_interval_hours: verifyIntervalHours.value,
        verify_max_median_ms: Math.max(1000, Number(verifyMaxMedianMs.value) || 10000),
        min_pool_size: Math.max(1, Number(minPoolSize.value) || 5),
        session_sticky_enabled: sessionStickyEnabled.value,
        passive_degrade_enabled: passiveDegradeEnabled.value,
        // 提交前夹一次区间：输入框可以是空的或被手动填成越界值，直接发出去
        // 会被后端 400 拒掉，而用户看到的是「保存失败」却不知道自己填错了什么。
        // 夹到边界至少是后端会接受的值，而真正想表达的意思由他再调。
        passive_degrade_first_byte_ms: clampDegradeFirstByteMs(
          passiveDegradeFirstByteMs.value,
        ),
        passive_degrade_cooldown_minutes: Math.min(
          1440,
          Math.max(1, Math.trunc(passiveDegradeCooldownMinutes.value || 15)),
        ),
      },
    }
    // 域名只在用户真的改过输入框时才提交，开关不参与。
    if (proxyDomainDirty.value) {
      body.proxy_domain = proxyDomainInput.value.trim()
    }
    const result = await saveOpenCodeIpPoolConfig(props.provider.id, body)
    domainSyncHint.value = legacyT('配置已保存')
    if (result.proxy_domain_changed > 0) {
      domainSyncHint.value = legacyT(`已保存（${result.proxy_domain_changed} 个端点与该域名一致）`)
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    // 用 getErrorMessage 而不是 `${err}`：后者会把 AxiosError 拼成
    // 「AxiosError: Request failed with status code 400」，后端指明
    // 是哪个字段越界的信息全丢了，只剩一个无用的状态码。
    errorMessage.value = legacyT(`保存配置失败：${getErrorMessage(err)}`)
  } finally {
    savingConfig.value = false
  }
}

/** 长任务轮询间隔。 */
const LONG_TASK_POLL_MS = 3000

/**
 * 轮询直到后台任务结束。
 *
 * 扫描/清理现在是「立刻 202 + 后台跑」，不能再靠一次请求的返回值判断结果：
 * 早期同步实现会让前端 HTTP 超时，用户看到「扫描失败」而后台其实还在跑。
 */
async function waitForLongTask(field: 'scanning' | 'cleaning' | 'verifying'): Promise<void> {
  for (;;) {
    await new Promise((resolve) => window.setTimeout(resolve, LONG_TASK_POLL_MS))
    if (unmounted.value) return
    await loadStatus()
    if (field === 'verifying') {
      if (!status.value?.verifying) return
      continue
    }
    if (!status.value?.[field]) return
  }
}

/** 三个长任务互斥：任何一个在跑，其余按钮都禁用。 */
const taskBusy = computed(
  () => !!(status.value?.scanning || verifying.value || status.value?.cleaning),
)

/** 长任务进度文案，例如「已探测 1523 / 3032（50%）」。
 *  复验的进度走独立字段——两个任务共用一组数字会互相覆盖。 */
const progressText = computed(() => {
  if (verifying.value) {
    const total = status.value?.verify_progress_total ?? 0
    const done = status.value?.verify_progress_done ?? 0
    if (total <= 0) return legacyT('正在准备复验…')
    const percent = Math.min(100, Math.round((done / total) * 100))
    // 进度分母是「IP 数 × 每 IP 采样次数」，337 × 3 会显示成 1011。只报这个
    // 数字，读者会以为有一千多个 IP 在排队。所以把 IP 数也摆出来，并说明这个
    // 倍数——验健康要求每一次采样都通过，不能只看中位数，任务粒度确实是采样。
    const targets = status.value?.verify_targets ?? 0
    if (targets > 0) {
      return legacyT(
        `复验 ${targets} 个 IP，每个采样 ${status.value?.verify_samples ?? 1} 次（已采样 ${done} / ${total}，${percent}%）`,
      )
    }
    return legacyT(`已采样 ${done} / ${total}（${percent}%）`)
  }
  const total = status.value?.progress_total ?? 0
  const done = status.value?.progress_done ?? 0
  if (!status.value?.scanning && !status.value?.cleaning) return ''
  if (total <= 0) return legacyT('正在准备探测…')
  const percent = Math.min(100, Math.round((done / total) * 100))
  return legacyT(`已探测 ${done} / ${total}（${percent}%）`)
})

async function handleVerify() {
  errorMessage.value = null
  try {
    await runOpenCodeIpPoolVerify(props.provider.id)
    verifying.value = true
    verifyRunning.value = true
    errorMessage.value = legacyT('复验已启动，正在按真实负载采样，可以离开本页面')
    emit('refresh')
    void waitForLongTask('verifying').then(() => {
      verifying.value = false
      verifyRunning.value = false
      if (unmounted.value) return
      const checked = status.value?.last_verify_checked ?? 0
      const kept = status.value?.last_verify_kept ?? 0
      const dropped = status.value?.last_verify_dropped ?? 0
      errorMessage.value = dropped
        ? legacyT(`复验完成：检查 ${checked} 个，保留 ${kept} 个，淘汰 ${dropped} 个`)
        : legacyT(`复验完成：检查 ${checked} 个，全部达标`)
      emit('refresh')
    })
  } catch (err) {
    errorMessage.value = legacyT(`启动复验失败：${err}`)
  }
}

async function handleScan() {
  errorMessage.value = null
  try {
    // 只负责「启动」。后台要跑几十分钟，按钮绝不能被占住——
    // 否则用户看到的是一个转 30 分钟的按钮，和卡死无法区分。
    await runOpenCodeIpPoolScan(props.provider.id)
    scanRunning.value = true
    errorMessage.value = legacyT('扫描已启动，正在后台探测，可以离开本页面')
    emit('refresh')
    // 轮询在后台跑，不 await，按钮立刻可用
    void waitForLongTask('scanning').then(() => {
      scanRunning.value = false
      if (unmounted.value) return
      const targets = status.value?.last_scan_targets ?? 0
      const found = status.value?.last_scan_found ?? 0
      const added = status.value?.last_scan_added ?? 0
      errorMessage.value =
        added > 0
          ? legacyT(`扫描完成：探测 ${targets} 个，新增 ${added} 个可用 IP`)
          : found > 0
            ? legacyT(`扫描完成：探测 ${targets} 个，其中 ${found} 个可达，但都已在池中，无需新增`)
            : legacyT(`扫描完成：探测 ${targets} 个，没有发现可达的 IP`)
      emit('refresh')
    })
  } catch (err) {
    errorMessage.value = legacyT(`启动扫描失败：${err}`)
  }
}

async function handleClean() {
  errorMessage.value = null
  try {
    await runOpenCodeIpPoolClean(props.provider.id)
    cleanRunning.value = true
    errorMessage.value = legacyT('清理已启动，正在后台探测，可以离开本页面')
    emit('refresh')
    void waitForLongTask('cleaning').then(() => {
      cleanRunning.value = false
      if (unmounted.value) return
      const checked = status.value?.last_clean_checked ?? 0
      const removed = status.value?.last_clean_removed ?? 0
      errorMessage.value =
        removed > 0
          ? legacyT(`清理完成：检查 ${checked} 个，移除 ${removed} 个失效 IP`)
          : legacyT(`清理完成：检查 ${checked} 个，没有需要移除的 IP`)
      emit('refresh')
    })
  } catch (err) {
    errorMessage.value = legacyT(`启动清理失败：${err}`)
  }
}

/**
 * 切换前置代理开关。
 *
 * 只提交 `proxy_enabled`：**不改写输入框、不改写端点**。
 * 开启时若输入框为空，本次请求就按默认官方域名走（后端 effective_proxy_domain
 * 会返回空），并给出提示；等填好域名再开即可。
 */
async function handleToggleProxy(enabled: boolean) {
  busy.value = true
  errorMessage.value = null
  const previous = proxyEnabled.value
  proxyEnabled.value = enabled
  try {
    const domain = proxyDomainInput.value.trim()
    const body: Record<string, unknown> = { proxy_enabled: enabled }
    // 顺手把当前输入框里的域名一起存下来（只在有内容时），避免开关后域名丢失。
    if (domain && proxyDomainDirty.value) {
      body.proxy_domain = domain
    }
    await saveOpenCodeIpPoolConfig(props.provider.id, body)
    if (enabled && !domain) {
      domainSyncHint.value = legacyT('已开启，但未填写域名，本次请求仍走默认官方地址')
    } else {
      domainSyncHint.value = enabled
        ? legacyT('已开启：本次请求使用输入框中的域名')
        : legacyT('已关闭：本次请求使用默认官方地址')
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    proxyEnabled.value = previous
    errorMessage.value = legacyT(`切换前置代理失败：${err}`)
    await loadStatus()
  } finally {
    busy.value = false
  }
}

async function handleRestoreOriginal() {
  busy.value = true
  errorMessage.value = null
  try {
    const result = await restoreOpenCodeOriginalBaseUrl(props.provider.id)
    await loadStatus()
    emit('refresh')
    errorMessage.value = result.errors?.length
      ? legacyT(`还原完成，${result.errors.length} 个端点失败：${result.errors.join('；')}`)
      : legacyT(`已还原 ${result.changed} 个端点为原始链接`)
  } catch (err) {
    errorMessage.value = legacyT(`还原失败：${err}`)
  } finally {
    busy.value = false
  }
}

/**
 * IP 池有两个来源，**不能混用**：
 * - provider：IP 存在 `opencode_scan.exit_pool`，增删改启停都走池接口，绝不碰密钥
 * - key：旧数据，IP 存在 key 元数据里，仍然按 key 操作
 * 走错分支就会出现「加一个 IP 就在密钥管理里多一条记录」这种问题。
 */
const isProviderPool = computed(() => (status.value?.pool_source ?? 'key') === 'provider')

async function handleAddIp() {
  const ip = normalizeIp(newIpInput.value)
  if (!ip) {
    errorMessage.value = legacyT(`无效 IP：${newIpInput.value.trim()}`)
    return
  }
  if (poolIps.value.some((row) => row.ip === ip)) {
    errorMessage.value = legacyT(`IP ${ip} 已在池中`)
    return
  }
  busy.value = true
  errorMessage.value = null
  try {
    if (isProviderPool.value) {
      await addOpenCodeExitIp(props.provider.id, ip)
    } else {
      await addProviderKey(props.provider.id, {
        name: `CDN IP ${ip}`,
        api_key: `public-${ip}`,
        auth_type: 'api_key',
        api_formats: ['openai:chat'],
        auto_fetch_models: false,
        note: 'opencode ip pool (manual)',
        upstream_metadata: { opencode_exit_ip: ip },
      })
    }
    newIpInput.value = ''
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`添加 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

function startEditIp(row: PoolIpRow) {
  editingRowIp.value = row.ip
  editingIp.value = row.ip
  errorMessage.value = null
}

async function commitEditIp(row: PoolIpRow) {
  const ip = normalizeIp(editingIp.value)
  if (!ip) {
    errorMessage.value = legacyT(`无效 IP：${editingIp.value.trim()}`)
    return
  }
  if (ip !== row.ip && poolIps.value.some((other) => other.ip === ip)) {
    errorMessage.value = legacyT(`IP ${ip} 已在池中`)
    return
  }
  busy.value = true
  errorMessage.value = null
  try {
    if (isProviderPool.value) {
      await updateOpenCodeExitIp(props.provider.id, row.ip, ip)
    } else {
      await updateProviderKey(row.key_id, {
        name: `CDN IP ${ip}`,
        upstream_metadata: { opencode_exit_ip: ip },
      })
    }
    editingRowIp.value = null
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`修改 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleToggleIp(row: PoolIpRow) {
  busy.value = true
  errorMessage.value = null
  try {
    if (isProviderPool.value) {
      await toggleOpenCodeExitIp(props.provider.id, row.ip, !row.is_active)
    } else {
      await updateProviderKey(row.key_id, { is_active: !row.is_active })
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`${row.is_active ? '停用' : '启用'} IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

async function handleDeleteIp(row: PoolIpRow) {
  busy.value = true
  errorMessage.value = null
  try {
    if (isProviderPool.value) {
      await removeOpenCodeExitIp(props.provider.id, row.ip)
    } else {
      await deleteEndpointKey(row.key_id)
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`删除 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  loadStatus()
})

watch(
  () => props.provider.id,
  () => loadStatus(),
)
</script>
