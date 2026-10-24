<template>
  <Card class="overflow-hidden" data-testid="opencode-ip-pool-panel">
    <!-- 头部：标题 + 面板级动作。
         「清理」按钮已删除：它与维护探针做的是同一件事，但清理是「失败即删、
         无阈值、无熔断」，一次点击就能把整池删光，属于危险入口。
         「扫描」入口也已删除：出口 IP 池改为纯手动维护（手工加 IP + 行内验证健康），
         不再按网段批量探测。
         定时维护 worker 也已下线，保洁改成手动「立即巡检」——所以这个按钮是现在唯一
         会让池子自己变好的入口，常驻在标题行，不随 tab 切换或状态加载消失。 -->
    <div class="p-4 border-b border-border/60 flex items-center justify-between gap-2">
      <h3 class="text-sm font-semibold">
        {{ legacyT('前置代理池') }}
      </h3>
      <Button
        variant="outline"
        size="sm"
        class="h-8 shrink-0"
        :disabled="busy || inspecting || !status"
        @click="handleRunMaintenance"
      >
        <Loader2 v-if="inspecting" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
        <Activity v-else class="mr-1.5 h-3.5 w-3.5" />
        {{ legacyT('立即巡检') }}
      </Button>
    </div>

    <!-- 前置代理域名（面板首要配置项） -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 space-y-2 bg-muted/20">
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <Globe class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-sm font-medium shrink-0">{{ legacyT('启用前置代理') }}</span>
          <!-- 开关只改本地状态：写库统一交给下面的「保存配置」按钮。
               以前这里点一下立即保存，同一个面板有两套保存语义。 -->
          <Switch v-model="proxyEnabled" :disabled="busy || savingConfig" />
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
      </div>
      <p v-if="!(proxyEnabled && proxyDomainInput)" class="text-[11px] text-muted-foreground">
        <template v-if="proxyEnabled">
          {{ legacyT('已开启但未填写域名，本次请求仍使用默认官方地址。') }}
        </template>
        <template v-else>
          {{ legacyT('关闭：本次请求使用默认官方地址。上方填写的域名会保留，随时可重新开启。') }}
        </template>
      </p>
    </div>

    <!-- 探测配置：网段与扫描相关的入口已删除，出口 IP 池纯手动维护。
         这块不再需要小标题——留下的都是探测/维护参数，上下每块本来就有分隔线，
         再加一个标题只是噪音。 -->
    <div class="px-4 py-3 border-b border-border/40 space-y-3">
      <!-- 扫描并发数、探测快筛阈值、后台巡检周期、自动补池全部删除：前三项只被已移除的
           CIDR 扫描与定时 worker 消费；「自动补池」是定时循环里的行为，定时器下线后它没有
           执行者。现在补池只有一条路——手动加 IP，或点「立即巡检」跑一轮。 -->
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label
            class="text-xs text-muted-foreground block mb-1.5"
            :title="legacyT('配额型失败（429）后的固定冷却。上游 Retry-After 只在更短时被采纳，不会把冷却放大')"
          >
            {{ legacyT('额度冷却 (秒)') }}
          </label>
          <Input
            v-model.number="cooldownSeconds"
            type="number"
            :min="COOLDOWN_SECONDS_MIN"
            :max="COOLDOWN_SECONDS_MAX"
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

      <!-- 「自动扫描」开关与「自动扫描间隔(小时)」已删除：那是旧的 key 级自动复验配置，
           后端早就不再读它（只被解析后丢弃），留着等于让人以为改它有作用。 -->
      <div class="grid grid-cols-2 gap-3">
        <div>
          <label
            class="text-xs text-muted-foreground block mb-1.5"
            :title="legacyT('真实请求连续失败多少次就把这个出口 IP 放进异常池。异常池里的 IP 不再参与轮转，等维护探针或行内验证判定健康后自动回到可用池；403/429 这类额度失败不计入')"
          >
            {{ legacyT('连续失败进异常 (次)') }}
          </label>
          <Input
            v-model.number="runtimeFailThreshold"
            type="number"
            min="1"
            max="100"
            class="h-8"
          />
        </div>
      </div>

      <div class="flex items-center justify-between border-t border-border/40 pt-3">
        <div class="flex items-center gap-2 min-w-0">
          <Repeat2 class="h-4 w-4 shrink-0 text-primary" />
          <span class="text-xs shrink-0">{{ legacyT('轮询规则') }}</span>
          <Switch v-model="rotationEnabled" />
          <Badge variant="secondary" class="text-[10px] h-4 px-1.5 shrink-0">
            {{
              rotationEnabled
                ? legacyT('按 /24 段随机，段内最多 2 路并发')
                : legacyT('沿用系统默认调度')
            }}
          </Badge>
        </div>
      </div>
      <!-- 池子偏小时提示补池。阈值取 32：低于它，会话粘性的收益已经
           撑不住（一个设备钉住一个节点就占掉 3% 的池）。补池只能靠手动加 IP，
           或由用户显式打开的手动加 IP 补，
           所以这里只提示当前数量。 -->
      <p v-if="needsMoreCandidates" class="text-[11px] text-amber-600 dark:text-amber-500">
        {{ legacyT('在用节点不足 32 个：可在下方标签栏右侧手动添加 IP。') }}
      </p>
      <!-- 跌破保底线（min_pool_size）：这时淘汰保护已生效、池子不再自动清理，
           但也意味着可用节点已经很少。必须显眼提示，别等到请求开始失败才发现。
           括号里那个数用「在用」池长度，不用 `healthy_count`：那是 chat 探针通过数，
           这个 provider 的池靠 TLS 零额度探针维护，该数恒为 0，显示出来就是「0 ≤ 5」。 -->
      <p
        v-if="status?.pool_below_floor"
        class="text-[11px] text-destructive font-medium"
      >
        {{
          legacyT(
            `可用节点已跌破保底线（${inUseCount} ≤ ${status?.min_pool_size ?? 0}）：淘汰保护已生效，请立即补池（手动加 IP / 启用备用链路）。`,
          )
        }}
      </p>
    </div>

    <!-- 健康维护：阈值与保底池大小。自动复验已删除——日常保洁由后台维护 worker
         用 TLS + GET / 零额度探针跑；真实 chat 探测只在行内「验证健康」按钮上发生。 -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40 space-y-3">
      <div class="flex items-center gap-2">
        <ShieldCheck class="h-4 w-4 text-primary" />
        <span class="text-xs font-semibold">{{ legacyT('健康维护') }}</span>
      </div>

      <!-- 旧的「验证延迟上限」（`opencode_health.verify_max_median_ms`）已删除：后端只把它
           读出来做展示，没有任何判定消费它，留着等于让人以为改它有作用。
           行内延迟着色改用固定阈值 SLOW_LATENCY_WARN_MS。删完只剩一项，不再套两列网格。 -->
      <div>
        <label class="text-xs text-muted-foreground block mb-1.5">
          {{ legacyT('保底池大小') }}
        </label>
        <Input v-model.number="minPoolSize" type="number" min="1" max="512" class="h-8" />
      </div>

      <!-- 单 IP「验证健康」用的探针参数：一次点击 = 一次真实 chat。 -->
      <div class="grid grid-cols-2 gap-3">
        <div class="col-span-2">
          <label
            class="text-xs text-muted-foreground block mb-1.5"
            :title="legacyT('行内「验证健康」用这个模型发一次真实 chat；填上游存在的免费模型名')"
          >
            {{ legacyT('探测模型') }}
          </label>
          <Input v-model="probeModel" class="h-8 font-mono text-sm" placeholder="big-pickle" />
        </div>
      </div>

      <p class="text-[11px] text-muted-foreground">
        {{
          legacyT('后台维护用 TLS + GET / 零额度探针；行内「验证健康」才发一次真实 chat。')
        }}
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
      </div>

      <!-- 保存按钮放在**所有**可改字段之后，而不是夹在探测配置块中间。
           它管的是整卡设置（探测、轮询、健康维护），而健康维护
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

    <!-- 状态条：在用 / 异常 / 段。
         「在用」与下面「在用」标签页严格同源（生效池长度，含被停用的——它们在列表里
         带「已停用」徽章），「段」是同一批 IP 按 /24 去重后的段数扣除停用/拉黑/异常，
         「异常」是异常池条目数。这里不放任何按钮——维护由后台 worker 自动跑。 -->
    <div class="px-4 py-3 border-b border-border/40">
      <div class="flex items-center gap-2 flex-wrap text-xs">
        <!-- 「健康」这一格已删除：它来自后端的 `healthy_count`（chat 探针通过数），
             而这个 provider 的池子靠 TLS + GET / 零额度探针维护，从不写 `healthy`，
             该数恒为 0 —— 表头上永远挂一个 0 只会让人以为池子全坏。
             现在两个数都与标签页同源：在用 = 生效池长度，异常 = 异常池条目数。 -->
        <span class="text-muted-foreground">{{ legacyT('在用') }}</span>
        <span class="font-mono tabular-nums text-primary">{{ inUseCount }}</span>
        <span class="text-muted-foreground/50">/</span>
        <span class="text-muted-foreground">{{ legacyT('异常') }}</span>
        <span class="font-mono tabular-nums">{{ abnormalCount }}</span>
        <span class="text-muted-foreground/50">·</span>
        <!-- 段数：在用 IP 覆盖了多少个 /24。配额与限速都是按段打下来的，
             只看 IP 个数看不出「一个 /24 里挤了 30 个」。 -->
        <span class="text-muted-foreground">{{ legacyT('段') }}</span>
        <span class="font-mono tabular-nums">{{ segmentCount }}</span>
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
    </div>

    <!-- 「最近运行统计」（上次扫描 / 探测目标 / 新增 IP）已随扫描入口一起删除：
         扫描改为纯手动、面板不再提供入口后，这三个数会永久冻结在最后一次扫描的值上，
         看着像「刚刚还在扫」，比没有更误导。 -->

    <!-- 节点明细：按可信度分两组（在用 / 异常）。
         分组本身就是信息——「异常」这一栏在出事时最有用：它直接回答了
         「池里那些慢节点是怎么进来的、被谁拦下的」。连续两轮不过的节点会被
         丢弃，而丢弃只写一条事件日志，所以这里没有「丢弃」栏可看。 -->
    <div v-if="status" class="px-4 py-3 border-b border-border/40">
      <!-- 标签栏不再自带 border-b：它下面紧跟着列头也有一条，两条线只隔几像素
           叠在一起，看起来像糊成一片，列头也就贴着上面那排统计读不出来。
           选中标签的 border-b-2 已经足够表明当前选中哪一组。 -->
      <!-- 池子靠手动维护（加 IP + 行内验证健康），验证通过的节点直接进生产池。
           key 只承担上游凭据，不再承载出口 IP，所以**池空 = 请求不做 DNS 锚定**
           （走官方域名）——这是最危险的一种静默降级，单独报警。 -->
      <div
        v-if="status?.pool_empty_alarm"
        class="mb-3 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs"
      >
        <div class="font-medium">
          {{ legacyT('出口 IP 池为空：当前所有请求都不做 DNS 锚定') }}
        </div>
        <div class="text-muted-foreground mt-0.5">
          {{ legacyT('key 只提供上游凭据，不再自带出口 IP。请在下方手动添加 IP，把节点填进池里。') }}
        </div>
      </div>
      <div v-else class="mb-3 text-xs text-muted-foreground">
        {{ legacyT('池模型：手动添加的 IP 经「验证健康」通过后写入生产池、立刻可用；后台维护按失败次数把不达标的节点送进异常池，累计到阈值才剔除（只记事件日志）。') }}
      </div>

      <!-- 手动添加 IP 挪到标签栏右侧：它原来在页面底部那块「全量列表」里，而那块与
           这两个标签页的内容是重复的（没有异常 IP 时两组完全一样）。写入口放在常驻的
           标签栏上，切 tab、翻页都不会把它带走，输入的 IP 也不会因为重新渲染而丢。 -->
      <div class="flex flex-wrap items-center gap-2 mb-3">
        <div class="flex items-center gap-1">
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
        <div class="flex items-center gap-2 ml-auto">
          <Input
            v-model="newIpInput"
            class="h-8 w-48 font-mono text-sm"
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
          <button
            v-if="showResetAbnormal"
            type="button"
            class="rounded border border-border px-2 py-1 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
            :disabled="busy"
            @click="handleResetAbnormal()"
          >
            {{ legacyT('重置全部异常') }}
          </button>
        </div>
      </div>

      <!-- 列头与两组列表共用同一套网格：IP 8rem / 延迟 5.5rem / 标记 1fr /
           成败 7.5rem / 验证 6.5rem。
           IP 列取 8rem 是按最长的 IPv4（15 字符）等宽字形留的余量；超长会 truncate
           而不是换行把行高撑开。表头和数据用同一套网格 + 同一套对齐方式。
           验证列从 3.5rem 放宽到 6.5rem：这一格不只要放按钮，探测结论（`✓ 120ms`
           / `✗ 3 次` / `限额`）必须持久显示在行内，3.5rem 只够那个按钮。
           分页工具条在滚动容器外面，只改变「渲染多少行」，不影响这里的列宽口径。
           标记列用 justify-center 而不是 text-center：徽章容器是 flex，
           text-align 对 flex 子元素不生效，必须同时改 justify。

           第三列表头按当前标签页给不同名字：在「在用」里是行内徽章（降级/保护/
           已停用），在「异常」里是原因与失败轮数。 -->
      <div class="max-h-64 overflow-y-auto">
        <!-- 粘性表头：列头和数据行必须在同一个滚动容器里。
             之前列头在容器外、数据行在 max-h-56 overflow-y-auto 里，在用 65 行、
             候选 272 行必然出纵向滚动条，滚动条把行的可用宽度挤窄约 15px 而列头
             不受影响，右侧那列就相对表头整体偏左。共用容器后两边内容盒完全
             相同，不会错位；做成 sticky 后滚动时表头也始终可见。 -->
        <div
          class="sticky top-0 z-10 bg-card grid grid-cols-[8rem_5.5rem_1fr_7.5rem_6.5rem] items-center gap-2 py-1.5 border-b border-border/40 text-[10px] uppercase tracking-wide text-muted-foreground/70"
        >
          <span class="truncate">{{ legacyT('IP') }}</span>
          <span class="text-center">{{ poolLatencyHeader }}</span>
          <span class="text-center truncate">{{ poolStatusHeader }}</span>
          <!-- 当日成败：成功/失败 · 最后成功（成功率只在悬停提示里）。
               后端没给 ip_stats 时整列显示 `-`，不隐藏——「没有数据」和
               「跑得很好」必须能区分开。 -->
          <span class="text-center truncate">{{ legacyT('成/败') }}</span>
          <span class="text-center">{{ legacyT('验证') }}</span>
        </div>

      <!-- 在用 -->
      <div v-if="poolTab === 'in_use'" class="text-xs">
        <p v-if="inUseRows.length === 0" class="text-muted-foreground py-2">
          {{ legacyT('没有可用节点：当前为直连代理模式，不做 CDN 锚定。') }}
        </p>
        <div v-else>
          <div
            v-for="row in pagedInUseRows"
            :key="row.ip"
            class="grid grid-cols-[8rem_5.5rem_1fr_7.5rem_6.5rem] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="font-mono truncate">{{ row.ip }}</span>
            <span
              class="font-mono tabular-nums text-center"
              :class="row.latencyMs > SLOW_LATENCY_WARN_MS ? 'text-amber-600' : 'text-muted-foreground'"
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
              <!-- 运行时证据：它刚刚失败了几次、是不是已经被 suspect 顶掉。
                   只在有失败时出现——没有这条证据的节点不该多一个「一切正常」的噪声徽章。 -->
              <Badge
                v-if="row.runtimeFails"
                variant="outline"
                class="text-[10px] h-4 px-1.5 border-amber-500/60 text-amber-600"
                :title="row.runtimeSuspectReason ? legacyT(`最近一次失败归因：${row.runtimeSuspectReason}`) : undefined"
              >
                {{ legacyT(`窗口内失败 ${row.runtimeFails} 次`) }}
              </Badge>
              <Badge
                v-if="row.cooling"
                variant="outline"
                class="text-[10px] h-4 px-1.5"
                :title="coolingBadgeTitle(row.coolingUntilMs)"
              >
                {{ coolingBadgeText(row.coolingUntilMs) }}
              </Badge>
              <!-- 行内减员：停用（留在池里，但请求路径跳过它）与删除（移出池）。
                   这两个入口原来只存在于页面底部那块与标签页重复的全量列表里，
                   那块删掉后必须挪进行内——池子现在是纯手动维护，没有别的减员入口。
                   删除不可撤销，所以走二次确认（见 handleDeleteIp）。 -->
              <span class="flex items-center gap-1 ml-1">
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-6 px-1 text-muted-foreground"
                  :disabled="busy"
                  :title="row.disabled ? legacyT('重新启用这个出口 IP') : legacyT('停用它：留在池里，但请求不再选它')"
                  @click="handleToggleIp(row.ip, row.disabled)"
                >
                  <Power class="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  class="h-6 px-1 text-muted-foreground hover:text-destructive"
                  :disabled="busy"
                  :title="legacyT('从出口池里删除这个 IP（二次确认）')"
                  @click="handleDeleteIp(row.ip)"
                >
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </span>
            </span>
            <!-- 当日成败：`12 / 3 · 14:22`。成功率移到 tooltip：三段挤在 7.5rem
                 里会先 truncate 掉最后成功时间，而那正是这一格最有用的信息。
                 任何一段缺失都退化成 `-`，绝不因为后端没给 ip_stats 或字段不全而报错。 -->
            <span
              class="font-mono tabular-nums text-[10px] leading-tight text-center truncate"
              :title="row.todayStatTitle"
            >
              <span :class="row.todayFail > 0 ? 'text-amber-600' : 'text-muted-foreground'">{{ row.todayStatText }}</span>
              <span class="text-muted-foreground"> · {{ row.todayLastOkText }}</span>
            </span>
            <!-- 单 IP「验证健康」：一次真实 chat 探测，只测这一行。
                 零额度探针是后台 worker 的事，这里必须是真实请求才有意义。
                 结论不能只写进 `:title`：写成 tooltip 等于点完界面上没有任何变化，
                 用户会以为按钮没反应。所以下面那行紧凑结论是持久显示的（保留到下一次
                 点击或页面刷新），完整文案（median_ms / reason）仍在 title 里。 -->
            <span class="flex flex-col items-center justify-center leading-tight">
              <button
                type="button"
                class="rounded border border-border px-1.5 py-0.5 text-[10px] leading-tight text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-50"
                :title="verifyCellTitle(row.ip)"
                :disabled="isVerifyingIp(row.ip)"
                @click="handleVerifyIp(row.ip)"
              >
                <Loader2 v-if="isVerifyingIp(row.ip)" class="h-3 w-3 animate-spin" />
                <template v-else>{{ legacyT('验证健康') }}</template>
              </button>
              <span
                v-if="row.verifyBadge"
                class="font-mono text-[10px] leading-tight mt-0.5"
                :class="verifyBadgeToneClass(row.verifyBadge.tone)"
              >
                {{ row.verifyBadge.text }}
              </span>
            </span>
          </div>
        </div>
      </div>

      <!-- 异常：有证据说明它有问题，先别用，但仍在跟踪 -->
      <div v-else-if="poolTab === 'abnormal'" class="text-xs">
        <p v-if="abnormalRows.length === 0" class="text-muted-foreground py-2">
          {{ legacyT('异常池为空：当前没有「有嫌疑但仍在跟踪」的节点。') }}
        </p>
        <div v-else>
          <div
            v-for="row in pagedAbnormalRows"
            :key="row.ip"
            class="grid grid-cols-[8rem_5.5rem_1fr_6.5rem] items-center gap-2 py-1 border-b border-border/20 last:border-0"
          >
            <span class="font-mono truncate">{{ row.ip }}</span>
            <span
              class="font-mono tabular-nums text-center text-muted-foreground"
              :title="row.whenTitle"
            >
              {{ row.whenText }}
            </span>
            <span class="flex items-center gap-2 justify-center">
              <Badge variant="outline" class="text-[10px] h-4 px-1.5">
                {{ row.reasonText }}
              </Badge>
              <Badge variant="secondary" class="text-[10px] h-4 px-1.5">
                {{ row.failsText }}
              </Badge>
              <span class="font-mono tabular-nums text-[10px] text-muted-foreground">
                {{ row.medianText }}
              </span>
              <Badge v-if="row.blocked" variant="outline" class="text-[10px] h-4 px-1.5">
                {{ legacyT('已拉黑') }}
              </Badge>
              <button
                v-if="!row.blocked"
                type="button"
                class="text-[11px] underline-offset-2 hover:underline disabled:opacity-50"
                :disabled="busy"
                @click="handleBlockIp(row.ip)"
              >
                {{ legacyT('拉黑') }}
              </button>
              <button
                v-else
                type="button"
                class="text-[11px] underline-offset-2 hover:underline disabled:opacity-50"
                :disabled="busy"
                @click="handleUnblockIp(row.ip)"
              >
                {{ legacyT('解禁') }}
              </button>
            </span>
            <!-- 异常节点复检：通过即清掉异常计数（回到轮转池）。
                 结论同样持久显示在行内，不只放在 title 里。 -->
            <span class="flex flex-col items-center justify-center leading-tight">
              <button
                type="button"
                class="rounded border border-border px-1.5 py-0.5 text-[10px] leading-tight text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-50"
                :title="verifyCellTitle(row.ip)"
                :disabled="isVerifyingIp(row.ip)"
                @click="handleVerifyIp(row.ip)"
              >
                <Loader2 v-if="isVerifyingIp(row.ip)" class="h-3 w-3 animate-spin" />
                <template v-else>{{ legacyT('验证健康') }}</template>
              </button>
              <span
                v-if="row.verifyBadge"
                class="font-mono text-[10px] leading-tight mt-0.5"
                :class="verifyBadgeToneClass(row.verifyBadge.tone)"
              >
                {{ row.verifyBadge.text }}
              </span>
            </span>
          </div>
        </div>
      </div>
      </div>

      <!-- 分页工具条：两组列表各自独立（页码与每页条数互不共享），放在滚动容器
           **外面**——它是固定导航，不该跟着行一起滚走。
           分页只影响渲染，不参与任何探测/统计；行内验证结论按 IP 存
           （`verifyIpBadges` / `verifyIpMessages`），翻页回来仍然是那一行的结论。 -->
      <div
        class="flex flex-wrap items-center gap-x-3 gap-y-1 pt-2 text-[11px] text-muted-foreground"
      >
        <span class="font-mono tabular-nums">{{ legacyT(`共 ${poolListTotal} 个`) }}</span>
        <div class="flex items-center gap-1 ml-auto">
          <button
            type="button"
            class="rounded border border-border px-2 py-0.5 transition-colors hover:bg-muted hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
            :disabled="poolListPage <= 1"
            @click="goPoolListPage(poolListPage - 1)"
          >
            {{ legacyT('上一页') }}
          </button>
          <span class="font-mono tabular-nums px-1">
            {{ legacyT(`第 ${poolListPage} / ${poolListPageCount} 页`) }}
          </span>
          <button
            type="button"
            class="rounded border border-border px-2 py-0.5 transition-colors hover:bg-muted hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
            :disabled="poolListPage >= poolListPageCount"
            @click="goPoolListPage(poolListPage + 1)"
          >
            {{ legacyT('下一页') }}
          </button>
        </div>
        <div class="flex items-center gap-1">
          <span>{{ legacyT('每页') }}</span>
          <button
            v-for="size in POOL_LIST_PAGE_SIZE_OPTIONS"
            :key="size"
            type="button"
            class="rounded border px-1.5 py-0.5 font-mono tabular-nums transition-colors"
            :class="
              size === poolListPageSize
                ? 'border-primary text-foreground'
                : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'
            "
            @click="setPoolListPageSize(size)"
          >
            {{ size }}
          </button>
        </div>
      </div>
    </div>

    <!-- 错误提示 -->
    <div
      v-if="errorMessage"
      class="px-4 py-2.5 bg-destructive/10 text-destructive text-xs border-t border-destructive/20"
    >
      {{ errorMessage }}
    </div>

    <!-- 验证健康的完整往返（请求 / 响应原文）。
         行内徽标只放得下结论，排查 403/429 要看的是上游原样正文，所以单独开弹窗。 -->
    <OpenCodeVerifyTraceDialog
      v-model:open="verifyTraceOpen"
      :result="verifyTraceResult"
    />
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import Badge from '@/components/ui/badge.vue'
import Button from '@/components/ui/button.vue'
import Card from '@/components/ui/card.vue'
import Input from '@/components/ui/input.vue'
import Switch from '@/components/ui/switch.vue'
import OpenCodeVerifyTraceDialog from './OpenCodeVerifyTraceDialog.vue'
import type { VerifyResult } from './OpenCodeVerifyTraceDialog.vue'
import {
  Activity,
  Globe,
  Loader2,
  Plus,
  Power,
  Repeat2,
  Save,
  ShieldCheck,
  Trash2,
} from 'lucide-vue-next'
import { useConfirm } from '@/composables/useConfirm'
import { useToast } from '@/composables/useToast'
import { useI18n } from '@/i18n'
import {
  addOpenCodeExitIp,
  blockOpenCodeExitIp,
  getOpenCodeIpPoolStatus,
  removeOpenCodeExitIp,
  resetOpenCodeAbnormalIps,
  runOpenCodeIpPoolMaintenance,
  saveOpenCodeIpPoolConfig,
  toggleOpenCodeExitIp,
  unblockOpenCodeExitIp,
  verifyOpenCodeExitIp,
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
/** 巡检结果是「一次操作的结果」，用完就散，用 toast 播报，不占面板的常驻错误条。 */
const { success: showSuccess, error: showError } = useToast()
const { confirm } = useConfirm()

const status = ref<OpenCodeIpPoolStatus | null>(null)
/**
 * 配额型冷却（秒）的合法区间，与后端
 * `MIN_OPENCODE_COOLDOWN_SECONDS` / `MAX_OPENCODE_COOLDOWN_SECONDS` 一致。
 *
 * 这是**固定短冷却**：上游 `Retry-After` 只在更短时被采纳，不会再把它放大
 * （2026-10-22 实测那个头指的是账户日额度刷新时间，而出口 IP 实际 2–3 分钟就恢复）。
 */
const COOLDOWN_SECONDS_DEFAULT = 120
const COOLDOWN_SECONDS_MIN = 30
const COOLDOWN_SECONDS_MAX = 600
/**
 * 行内延迟的着色阈值（毫秒）：超过它就把这一格的延迟标成琥珀色。
 *
 * 以前这个阈值是「验证延迟上限」（`opencode_health.verify_max_median_ms`）的 70%，
 * 但那个配置项已被删除——后端只把它读出来展示，没有任何判定消费它。
 * 固定成 7000（旧默认 10000 的 70%）保持原有观感。
 */
const SLOW_LATENCY_WARN_MS = 7000
/**
 * 上一次从服务端拿到的状态，用来判断某个字段有没有被用户改过。
 * 见 keepUserEdit：本地值不再等于这里的值，就说明用户正在编辑它。
 */
const lastServerStatus = ref<OpenCodeIpPoolStatus | null>(null)
/** 真实请求连续失败多少次把 IP 放进异常池（后端 `runtime_fail_threshold`）。 */
const runtimeFailThreshold = ref<number>(3)
const rotationEnabled = ref(false)
const cooldownSeconds = ref<number>(COOLDOWN_SECONDS_DEFAULT)
const rotationCursor = ref<number>(0)
const rotationPoolSize = ref<number>(0)
const rotationLastIp = ref<string>('')

/**
 * 上次实际命中的位置（从 0 起；-1 表示暂时算不出来）。
 *
 * 这里**不能**用 rotation_cursor % rotation_pool_size 去算位置：请求路径里的
 * 取模基数是「可用」池，即生产集合剔除手工停用和冷却中的节点
 * （见 opencode_rotation::pick_anchor_ip 里的 usable），而
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
// 降级计数与空池告警：纯展示，服务端给什么就显示什么。
// 「在用 / 异常」两个数不在这里——它们与两个标签页同源，由行数据长度算出（见下方）。
const degradedCount = ref<number>(0)
const poolEmpty = ref<boolean>(false)
/** 单 IP「验证健康」的探测模型（真实 chat）。 */
const probeModel = ref<string>('big-pickle')
/**
 * 正在验证的 IP 集合（行内按钮的 loading）。
 *
 * 用集合而不是一个布尔：只锁住被点的那一行，其它行可以同时各验各的；
 * 后端一次只处理一个请求，但按 IP 记录才能给出「这一行在转」的准确反馈。
 */
const verifyingIps = ref<Set<string>>(new Set())
/**
 * 每行最近一次验证的**完整**结论文案（含 `median_ms` / `reason`），只进 `:title`。
 */
const verifyIpMessages = ref<Record<string, string>>({})
/**
 * 每行最近一次验证的**紧凑**结论，直接渲染在「验证」格子里。
 *
 * 为什么必须可见：只写进 `:title` 时，点完按钮界面上没有任何变化，用户会以为
 * 按钮没反应。这里保留到下一次点击（点击瞬间先清空）或页面刷新，不做定时消失——
 * 探测要花一次真实 chat 的钱，结论不该几秒后就看不见。
 */
const verifyIpBadges = ref<Record<string, VerifyBadge>>({})
/**
 * 最近一次「验证健康」的完整响应（含后端新增的 `trace`：真实发出的请求与收到的响应）。
 *
 * 行内徽章只放得下结论；排查 403/429 时真正要看的是上游原样的响应正文，
 * 所以整份响应单独存起来交给弹窗展示。弹窗只读它，不参与任何落账逻辑。
 */
const verifyTraceResult = ref<VerifyResult | null>(null)
const verifyTraceOpen = ref(false)
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

type PoolTabKey = 'in_use' | 'abnormal'
const poolTab = ref<PoolTabKey>('in_use')

interface PoolNodeRow {
  ip: string
  latencyMs: number
  latencyText: string
  degraded: boolean
  pinned: boolean
  disabled: boolean
  /** 窗口（1 小时）内的运行时失败次数；`null` = 没有失败证据。 */
  runtimeFails: number | null
  /** `suspect` 的原因标签（`transport` / `gateway_timeout` / `slow_first_byte`）。 */
  runtimeSuspectReason: string | null
  /** 是否正被 `suspect` 冷却顶着（选择路径下一轮会绕开它）。 */
  cooling: boolean
  /** 冷却到期时刻（毫秒时间戳）；不在冷却时为 `null`。用于每秒倒计时。 */
  coolingUntilMs: number | null
  /** 今日成功次数（没有计数时为 0，只用于着色）。 */
  todayOk: number
  /** 今日失败次数（没有计数时为 0，只用于着色）。 */
  todayFail: number
  /** `12 / 3`，没有计数时 `-`。 */
  todayStatText: string
  /** 最后成功 `HH:mm`，没有时 `-`。 */
  todayLastOkText: string
  /** 悬停提示（成功率、失败分档都在里面）。 */
  todayStatTitle: string | undefined
  /** 行内显示的验证结论；没验证过时为 `null`（只显示按钮）。 */
  verifyBadge: VerifyBadge | null
}

/** 行内验证结论的语气：决定颜色，正文由 `text` 给出。 */
type VerifyBadgeTone = 'ok' | 'fail' | 'quota' | 'error'

interface VerifyBadge {
  tone: VerifyBadgeTone
  /** 紧凑形式：`✓ 120ms` / `✗ 3 次` / `限额` / `错误`。 */
  text: string
}

function formatLatency(ms?: number | null): string {
  if (ms == null) return '—'
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms}ms`
}

/**
 * RFC3339 → `MM-DD HH:MM`。
 *
 * 面板这一列只有 5.5rem 宽，秒与时区都没有信息量；截成 `MM-DD HH:MM` 才放得下
 * （等价信息放在 `title` 里，需要精确值时鼠标悬停可见）。
 */
function formatShortTimestamp(value?: string | null): string {
  if (!value) return '—'
  return value.slice(5, 16).replace('T', ' ')
}

function isPinned(ip: string): boolean {
  return (status.value?.pinned || []).includes(ip)
}

function isDisabled(ip: string): boolean {
  return (status.value?.exit_pool_disabled || []).includes(ip)
}

/** 是否被人工拉黑（请求路径永远跳过，复验也不放回）。 */
function isBlocked(ip: string): boolean {
  return (status.value?.blocked || []).includes(ip)
}

/**
 * 异常原因文案。
 *
 * 三分法对应三种真实故障：完全连不上、连上了但部分采样超时、每次都答但太慢。
 * 只报「异常」而不说哪一种，等于把排查方向也一起藏了。
 */
function abnormalReasonText(reason: string): string {
  if (reason === 'unreachable') return legacyT('连不上')
  if (reason === 'partial_timeout') return legacyT('部分超时')
  if (reason === 'too_slow') return legacyT('延迟超标')
  return reason
}

/**
 * 运行时证据：ip → { 失败次数, 可疑原因, 是否冷却中, 冷却剩余秒 }。
 *
 * 后端回传两种节点：有失败计数的，以及「只冷却、无失败计数」的（看门狗超时与额度类
 * 冷却都不写失败计数）。查不到就是干净的。
 */
const runtimeEvidence = computed(() => {
  const map = new Map<
    string,
    { fails: number; suspectReason: string | null; cooling: boolean; coolingSeconds: number | null }
  >()
  for (const item of status.value?.runtime_evidence || []) {
    map.set(item.ip, {
      fails: item.fails,
      suspectReason: item.suspect_reason ?? null,
      cooling: item.cooling,
      coolingSeconds: item.cooldown_remaining_seconds ?? null,
    })
  }
  return map
})

// ---- 当日成败计数（`ip_stats`）--------------------------------------------
//
// 后端每个出口 IP 记 `{ok, fail, by_status, last_ok_at, last_fail_at}`（unix 秒）。
// 这里的一切都按「可以没有」写：接口没返回 `ip_stats`、字段缺一半、值不是数字、
// 老版本后端根本没有这个字段 —— 一律退化成 `-`，绝不抛错、绝不显示 `NaN%`。

interface IpStatView {
  ok: number
  fail: number
  /** `ok/(ok+fail)`；两者都是 0 时为 `null`。 */
  rate: number | null
  lastOkAt: number | null
  byStatus: Record<string, number>
}

function safeCount(value: unknown): number {
  const parsed = Number(value ?? 0)
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0
}

function readIpStat(raw: unknown): IpStatView | null {
  if (!raw || typeof raw !== 'object') return null
  const record = raw as Record<string, unknown>
  const ok = safeCount(record.ok)
  const fail = safeCount(record.fail)
  const total = ok + fail
  const lastOkAt = safeCount(record.last_ok_at)
  const byStatus: Record<string, number> = {}
  const rawByStatus = record.by_status
  if (rawByStatus && typeof rawByStatus === 'object') {
    for (const [bucket, count] of Object.entries(rawByStatus as Record<string, unknown>)) {
      const parsed = safeCount(count)
      if (parsed > 0) byStatus[bucket] = parsed
    }
  }
  return { ok, fail, rate: total > 0 ? ok / total : null, lastOkAt: lastOkAt > 0 ? lastOkAt : null, byStatus }
}

const ipStatIndex = computed(() => {
  const map = new Map<string, IpStatView>()
  const raw = status.value?.ip_stats
  if (!raw || typeof raw !== 'object') return map
  for (const [ip, value] of Object.entries(raw)) {
    const parsed = readIpStat(value)
    if (parsed && parsed.ok + parsed.fail > 0) map.set(ip, parsed)
  }
  return map
})

/** 取某个 IP 的计数；查不到就是 `undefined`（面板据此显示 `-`）。 */
function ipStatFor(ip: string): IpStatView | undefined {
  return ipStatIndex.value.get(ip)
}

/**
 * unix 秒 → `HH:mm`（当天）或 `MM-DD HH:mm`（跨天）。
 *
 * 这一列只有几 rem 宽，秒没有信息量；跨天时补上日期，否则「昨天 23:50」会看起来
 * 像刚成功过。
 */
function formatStatTime(unixSeconds: number | null): string {
  if (unixSeconds == null) return '-'
  const at = new Date(unixSeconds * 1000)
  if (Number.isNaN(at.getTime())) return '-'
  const pad = (value: number) => String(value).padStart(2, '0')
  const clock = `${pad(at.getHours())}:${pad(at.getMinutes())}`
  const now = new Date()
  const sameDay =
    at.getFullYear() === now.getFullYear() &&
    at.getMonth() === now.getMonth() &&
    at.getDate() === now.getDate()
  return sameDay ? clock : `${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${clock}`
}

/**
 * 成功率 `ok/(ok+fail)` → `86%`。
 *
 * 分母为 0、字段缺失或不是数字时返回 `-`：行内已经不放百分比了，但它还出现在
 * 悬停提示里，`NaN%` 比没有更糟。
 */
function formatRate(rate: number | null): string {
  if (rate == null || !Number.isFinite(rate)) return '-'
  return `${Math.round(rate * 100)}%`
}

/**
 * 悬停提示：把「按状态分档」和成功率都交代清楚。
 *
 * 成功率只在这里出现——行内三段（成功/失败 · 成功率 · 最后成功）挤在 7.5rem 里
 * 会先截掉最后成功时间，那是这一格最有用的信息。
 */
function statTitle(stat: IpStatView | undefined): string | undefined {
  if (!stat) return legacyT('今日暂无成败计数（接口未返回 ip_stats，或该节点今天还没有请求）')
  const buckets = Object.entries(stat.byStatus)
    .map(([bucket, count]) => `${bucket}: ${count}`)
    .join(' / ')
  const parts = [
    legacyT(`今日成功 ${stat.ok} 次、失败 ${stat.fail} 次`),
    stat.rate != null ? legacyT(`成功率 ${formatRate(stat.rate)}`) : null,
    buckets ? legacyT(`失败分类 ${buckets}`) : null,
    stat.lastOkAt != null ? legacyT(`最后成功 ${formatStatTime(stat.lastOkAt)}`) : null,
  ].filter(Boolean)
  return parts.join('；')
}

/**
 * 每秒跳一次的时钟：只为了让「冷却中」徽章显示倒计时。
 *
 * 间隔只在**确实有节点在冷却**时才开（空闲面板不该每秒重渲染一次）。
 */
const coolingClockMs = ref(Date.now())
let coolingClockTimer: ReturnType<typeof setInterval> | undefined

function coolingSecondsLeft(untilMs: number | null): number | null {
  if (untilMs == null) return null
  return Math.max(0, Math.round((untilMs - coolingClockMs.value) / 1000))
}

/** 倒计时文案：`12h05m` / `49m12s` / `37s`。 */
function formatCooldownCountdown(secondsLeft: number): string {
  if (secondsLeft <= 0) return legacyT('即将到期')
  const hours = Math.floor(secondsLeft / 3600)
  const minutes = Math.floor((secondsLeft % 3600) / 60)
  const seconds = secondsLeft % 60
  if (hours > 0) return `${hours}h${String(minutes).padStart(2, '0')}m`
  if (minutes > 0) return `${minutes}m${String(seconds).padStart(2, '0')}s`
  return `${seconds}s`
}

/** 「冷却中」徽章文案（带倒计时）。 */
function coolingBadgeText(untilMs: number | null): string {
  const left = coolingSecondsLeft(untilMs)
  return left == null ? legacyT('冷却中') : `${legacyT('冷却中')} ${formatCooldownCountdown(left)}`
}

/** 悬停提示：冷却到几点（配额型 429 会跟上游 `retry-after` 对齐，可能是几小时后）。 */
function coolingBadgeTitle(untilMs: number | null): string | undefined {
  if (untilMs == null) return undefined
  return legacyT(`冷却至 ${new Date(untilMs).toLocaleTimeString()}`)
}

/** 在用：当前参与轮转的节点，带实测延迟与状态标记。 */
const inUseRows = computed<PoolNodeRow[]>(() =>
  (status.value?.healthy || status.value?.exit_pool || []).map((ip) => {
    const latencyMs = status.value?.latencies?.[ip] ?? Number.POSITIVE_INFINITY
    const evidence = runtimeEvidence.value.get(ip)
    const stat = ipStatFor(ip)
    return {
      ip,
      latencyMs,
      latencyText: formatLatency(status.value?.latencies?.[ip]),
      degraded: (status.value?.degraded || []).includes(ip),
      pinned: isPinned(ip),
      disabled: isDisabled(ip),
      runtimeFails: evidence?.fails ?? null,
      runtimeSuspectReason: evidence?.suspectReason ?? null,
      cooling: evidence?.cooling ?? false,
      coolingUntilMs:
        evidence?.cooling && evidence.coolingSeconds != null
          ? Date.now() + evidence.coolingSeconds * 1000
          : null,
      todayOk: stat?.ok ?? 0,
      todayFail: stat?.fail ?? 0,
      todayStatText: stat ? `${stat.ok} / ${stat.fail}` : '-',
      todayLastOkText: formatStatTime(stat?.lastOkAt ?? null),
      todayStatTitle: statTitle(stat),
      verifyBadge: verifyIpBadges.value[ip] ?? null,
    }
  }),
)

/**
 * `/24` 段键：取前三段（与后端 `opencode_pool::ipv4_segment_key` 等价）。
 *
 * 非法 IP 返回 `null`，让调用方跳过——池里混进一条脏数据不该把段数算成 `NaN`。
 */
function ipv4SegmentKey(ip: string): string | null {
  const parts = ip.trim().split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : NaN))
  if (octets.some((octet) => !Number.isFinite(octet) || octet < 0 || octet > 255)) return null
  return `${octets[0]}.${octets[1]}.${octets[2]}`
}

/**
 * 在用池覆盖的 `/24` 段数。
 *
 * 口径与「在用」那个数严格同源：当前生效池（`exit_pool`，后端已剔除
 * abnormal/blocked）再减掉 `exit_pool_disabled`，然后按 `/24` 去重。
 *
 * 为什么在前端算：状态接口只给逐 IP 的数组，没有 `segments` 之类按段统计的字段
 * （后端的 `ipv4_segment_key` 只在扫描去重时内部使用，不进响应）。段数就是
 * 数组的纯函数，前端算不引入任何额外请求。
 */
const segmentCount = computed(() => {
  const disabled = new Set(status.value?.exit_pool_disabled || [])
  const blocked = new Set(status.value?.blocked || [])
  const abnormal = new Set((status.value?.abnormal || []).map((entry) => entry.ip))
  const segments = new Set<string>()
  for (const ip of status.value?.exit_pool || []) {
    if (disabled.has(ip) || blocked.has(ip) || abnormal.has(ip)) continue
    const key = ipv4SegmentKey(ip)
    if (key) segments.add(key)
  }
  return segments.size
})

/**
 * 冷却倒计时的时钟：只有在**确实有节点在冷却**时才每秒跳一次。
 *
 * 配额型 429 的冷却可长达十几小时，光写「冷却中」看不出还剩多久；空闲时（没有冷却
 * 节点）不跑定时器，避免整块面板每秒重渲染。
 */
const coolingRowsPresent = computed(() =>
  inUseRows.value.some((row) => row.coolingUntilMs != null),
)

watch(
  coolingRowsPresent,
  (active) => {
    if (active && coolingClockTimer === undefined) {
      coolingClockMs.value = Date.now()
      coolingClockTimer = setInterval(() => {
        coolingClockMs.value = Date.now()
      }, 1000)
      return
    }
    if (!active && coolingClockTimer !== undefined) {
      clearInterval(coolingClockTimer)
      coolingClockTimer = undefined
    }
  },
  { immediate: true },
)

onUnmounted(() => {
  if (coolingClockTimer !== undefined) {
    clearInterval(coolingClockTimer)
    coolingClockTimer = undefined
  }
})

/** 异常：先别用，但仍在跟踪；出路是行内「验证健康」通过或累计到阈值被剔除。 */
const abnormalRows = computed(() =>
  (status.value?.abnormal || []).map((entry) => ({
    ip: entry.ip,
    failsText: legacyT(`${entry.fails} 轮`),
    medianText: formatLatency(entry.median_ms ?? undefined),
    whenText: formatShortTimestamp(entry.since),
    whenTitle: entry.since,
    reasonText: abnormalReasonText(entry.reason),
    blocked: isBlocked(entry.ip),
    verifyBadge: verifyIpBadges.value[entry.ip] ?? null,
  })),
)

/**
 * 标签顺序按**可信度**排：在用（正在轮转）→ 异常（出问题待跟踪）。
 *
 * 默认选中的是「在用」（见 `poolTab` 的初始值）——打开面板时最关心的是"现在到底在用哪些 IP"。
 */
const poolTabs = computed(() => [
  { key: 'in_use' as const, label: legacyT('在用'), count: inUseCount.value },
  { key: 'abnormal' as const, label: legacyT('异常'), count: abnormalCount.value },
])

/**
 * 头部状态条的两个数，与两个标签页严格同源（标签上的 count 就是这两个长度）。
 *
 * 不读后端的 `healthy_count` / `in_use_count`：前者是 chat 探针通过数，这个 provider
 * 的池子靠 TLS + GET / 零额度探针维护，从不写 `healthy`，该数恒为 0；
 * 后者与「生效池长度」在停用节点上口径不一致。直接数行既不会漂，也永远和标签页对得上。
 */
const inUseCount = computed(() => inUseRows.value.length)
const abnormalCount = computed(() => abnormalRows.value.length)

/**
 * 「在用」/「异常」两组列表的分页状态。
 *
 * 生产有效池上千个 IP 时一次渲染全部行既卡又没法定位。分页只影响**渲染**：
 * 不参与任何探测、统计或落账逻辑。两组各自独立（页码与每页条数都不共享），
 * 切 tab 不会把页码带过去。默认每页 50。
 */
type PoolListPaging = { page: number; pageSize: number }

const POOL_LIST_PAGE_SIZE_OPTIONS = [50, 100, 200] as const

const poolListPaging = reactive<Record<PoolTabKey, PoolListPaging>>({
  in_use: { page: 1, pageSize: 50 },
  abnormal: { page: 1, pageSize: 50 },
})

/** 当前标签页那一组的分页状态。 */
function poolListPagingFor(tab: PoolTabKey): PoolListPaging {
  return poolListPaging[tab]
}

/** 当前标签页的总行数（分页只切这一个数，不参与别处统计）。 */
const poolListTotal = computed(() =>
  poolTab.value === 'in_use' ? inUseRows.value.length : abnormalRows.value.length,
)

/** 当前标签页的总页数（至少 1 页：空列表也要显示「第 1 / 1 页」而不是「第 1 / 0 页」）。 */
const poolListPageCount = computed(() =>
  Math.max(1, Math.ceil(poolListTotal.value / poolListPagingFor(poolTab.value).pageSize)),
)

/**
 * 当前页（读取时夹紧）。
 *
 * 夹紧必须发生在**读**这一侧：池子从 1086 个掉到 60 个时，若只在下一次交互里
 * 才修正 `page`，中间会先渲染出一页空白，看起来像「列表没了」。
 */
const poolListPage = computed(() => {
  const paging = poolListPagingFor(poolTab.value)
  return Math.min(poolListPageCount.value, Math.max(1, paging.page))
})

const poolListPageSize = computed(() => poolListPagingFor(poolTab.value).pageSize)

/** 切页：夹在 `[1, 总页数]` 之间，越界的调用直接落回边界页。 */
function goPoolListPage(page: number) {
  const paging = poolListPagingFor(poolTab.value)
  paging.page = Math.min(poolListPageCount.value, Math.max(1, page))
}

/** 换每页条数：回到第 1 页，否则当前页会莫名其妙跳到别的位置。 */
function setPoolListPageSize(size: number) {
  const paging = poolListPagingFor(poolTab.value)
  paging.pageSize = size
  paging.page = 1
}

/** 把两组页码都按当前行数夹一次（行数变化后不留越界页）。 */
function clampPoolListPages() {
  const totals: Record<PoolTabKey, number> = {
    in_use: inUseRows.value.length,
    abnormal: abnormalRows.value.length,
  }
  for (const tab of ['in_use', 'abnormal'] as const) {
    const paging = poolListPaging[tab]
    const pages = Math.max(1, Math.ceil(totals[tab] / paging.pageSize))
    paging.page = Math.min(pages, Math.max(1, paging.page))
  }
}

watch([() => inUseRows.value.length, () => abnormalRows.value.length], () => {
  clampPoolListPages()
})

/** 取某一页的行（读取侧再夹一次，避免越界页先闪一帧空白）。 */
function pagedPoolRows<T>(rows: T[], paging: PoolListPaging): T[] {
  const pages = Math.max(1, Math.ceil(rows.length / paging.pageSize))
  const page = Math.min(pages, Math.max(1, paging.page))
  const start = (page - 1) * paging.pageSize
  return rows.slice(start, start + paging.pageSize)
}

const pagedInUseRows = computed(() => pagedPoolRows(inUseRows.value, poolListPaging.in_use))
const pagedAbnormalRows = computed(() =>
  pagedPoolRows(abnormalRows.value, poolListPaging.abnormal),
)

/**
 * 第三列表头。同一列在两组列表里装的是不同的东西：「在用」是行内徽章（降级/
 * 保护/已停用）+ 行内减员按钮（停用/删除），「异常」是原因 + 失败轮数。
 * 统一写「状态」是把几个不同维度混为一谈；「在用」这一侧多带了两个按钮，
 * 所以补上「操作」二字，免得用户找不到删除入口。
 */
const poolStatusHeader = computed(() =>
  poolTab.value === 'in_use' ? legacyT('标记 / 操作') : legacyT('原因 / 失败轮数'),
)

/**
 * 第二列表头。同样是按标签页换名字：在用看的是**实测延迟**，异常看的是
 * **加入时间**（回答「它什么时候开始有问题」）。
 */
const poolLatencyHeader = computed(() => {
  if (poolTab.value === 'abnormal') return legacyT('加入时间')
  return legacyT('延迟')
})

/** 异常池是否值得显示「重置全部异常」：有内容才显示。 */
const showResetAbnormal = computed(() => (status.value?.abnormal_count ?? 0) > 0)

const savingConfig = ref(false)
const busy = ref(false)
/**
 * 巡检进行中的标志。
 *
 * 单独一个 ref 而不是复用 `busy`：巡检要花十几秒，期间不该把「验证健康」「保存配置」
 * 这类无关按钮一起锁死；它只需要锁住自己，防重复点击。
 */
const inspecting = ref(false)

/** 在用节点低于此值就提示补池。 */
const LOW_POOL_HINT_THRESHOLD = 32

/**
 * 是否该提示补池。
 *
 * 池子为空时**不提示**：空池是「走域名直连代理」这一合法模式，实测
 * 150K 下 4552ms，是整个调查里最稳的结果。把它报成待修复的问题，
 * 会诱导使用者去填补一个他们并不需要填的洞。
 *
 * 判据用「在用」池长度，不用 `healthy_count`：后者是 chat 探针通过数，这个 provider
 * 上恒为 0，拿它做比较等于让这条提示永远不出现。
 */
const needsMoreCandidates = computed(() => {
  if (!status.value || poolEmpty.value) return false
  return inUseCount.value > 0 && inUseCount.value < LOW_POOL_HINT_THRESHOLD
})

const errorMessage = ref<string | null>(null)
const proxyDomainInput = ref('')
const newIpInput = ref('')
const domainSyncHint = ref('')

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

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

/**
 * 前置代理开关状态。
 *
 * 独立于端点主机：端点 base_url 始终是真实上游，不会被开关改写。
 * 开关只决定「本次请求用输入框里的域名」还是「用默认官方域名」，
 * 而且**不会改写输入框**——输入框里的域名只归用户所有。
 */
const proxyEnabled = ref(false)

/**
 * 这个 IP 是否已经在池里（含停用/异常/拉黑的条目）。
 *
 * 保留这层前端判重只为了给一句能看懂的提示：直接交给后端会变成一条 400，
 * 用户只能看到一个状态码。以前它比对的是底部「全量列表」的行，那块列表已删除，
 * 改为直接查 `pool_ips`（状态接口本来就带着全量条目）。
 */
function poolHasIp(ip: string): boolean {
  return (status.value?.pool_ips || []).some((row) => row?.ip === ip)
}

const configDirty = computed(
  () =>
    // 连续失败阈值走同一个保存按钮，
    // 漏掉脏检查会让「改了但保存按钮不亮」。
    runtimeFailThreshold.value !== (status.value?.runtime_fail_threshold ?? 3) ||
    // 前置代理开关与域名现在也走同一个保存按钮：漏掉脏检查会「改了但按钮不亮」。
    proxyEnabled.value !== (status.value?.proxy_enabled ?? false) ||
    (proxyDomainInput.value.trim() !== '' &&
      proxyDomainInput.value.trim() !== (status.value?.saved_proxy_domain || '')) ||
    rotationEnabled.value !== (status.value?.rotation_enabled ?? false) ||
    clampCooldownSeconds(cooldownSeconds.value) !==
      clampCooldownSeconds(status.value?.cooldown_seconds) ||
    // 健康维护段也在同一个「保存配置」按钮里，脏检查必须一并覆盖。
    Math.max(1, Number(minPoolSize.value) || 5) !== (status.value?.min_pool_size ?? 5) ||
    probeModel.value.trim() !== (status.value?.probe_model ?? 'big-pickle') ||
    sessionStickyEnabled.value !== (status.value?.session_sticky_enabled ?? false),
)

function clampCooldownSeconds(value?: number | null): number {
  if (value == null || !Number.isFinite(Number(value))) return COOLDOWN_SECONDS_DEFAULT
  const rounded = Math.trunc(Number(value))
  return Math.min(COOLDOWN_SECONDS_MAX, Math.max(COOLDOWN_SECONDS_MIN, rounded))
}

/**
 * 用户改过、但还没保存的字段，不能被一次后台刷新静默丢掉。
 *
 * 判据不是「服务端哪个字段变了」，而是「本地值是否还等于上次拿到的服务端值」：
 * 相等说明用户没动过，可以放心用新值覆盖；不等就是他正在编辑，必须留着。
 * 面板里任何别的操作（验证健康、增删 IP、切换前置代理）结束都会走到
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

    runtimeFailThreshold.value = keepUserEdit(
      runtimeFailThreshold.value,
      previous?.runtime_fail_threshold ?? 3,
      next.runtime_fail_threshold ?? 3,
    )
    rotationEnabled.value = keepUserEdit(rotationEnabled.value, previous?.rotation_enabled ?? false, next.rotation_enabled ?? false)
    cooldownSeconds.value = keepUserEdit(
      cooldownSeconds.value,
      clampCooldownSeconds(previous?.cooldown_seconds),
      clampCooldownSeconds(next.cooldown_seconds),
    )
    minPoolSize.value = keepUserEdit(minPoolSize.value, previous?.min_pool_size ?? 5, next.min_pool_size ?? 5)
    probeModel.value = keepUserEdit(
      probeModel.value,
      previous?.probe_model ?? 'big-pickle',
      next.probe_model ?? 'big-pickle',
    )
    sessionStickyEnabled.value = keepUserEdit(sessionStickyEnabled.value, previous?.session_sticky_enabled ?? false, next.session_sticky_enabled ?? false)

    // 下面这些是纯展示，用户改不了，一律以服务端为准。
    rotationCursor.value = next.rotation_cursor ?? 0
    rotationPoolSize.value = next.rotation_pool_size ?? (next.exit_pool || []).length
    rotationLastIp.value = next.rotation_last_ip ?? ''
    degradedCount.value = next.degraded_count ?? (next.degraded || []).length
    poolEmpty.value = next.pool_empty ?? false
    sessionStickyActive.value = next.session_sticky_active ?? false
    sessionStickyReason.value = next.session_sticky_disabled_reason ?? null
    proxyEnabled.value = next.proxy_enabled ?? false
    // 输入框只做「首次预填」：已有内容（包括用户刚输入但没保存的）一律不动，
    // 开关也不参与写入。域名只归用户所有。
    if (!proxyDomainInput.value.trim()) {
      proxyDomainInput.value = next.saved_proxy_domain || ''
    }
    lastServerStatus.value = next
    errorMessage.value = null
  } catch (err) {
    errorMessage.value = legacyT(`加载前置代理池状态失败：${err}`)
  }
}

async function handleSaveConfig() {
  savingConfig.value = true
  errorMessage.value = null
  try {
    const body: Record<string, unknown> = {
      rotation_enabled: rotationEnabled.value,
      cooldown_seconds: clampCooldownSeconds(cooldownSeconds.value),
      // 后台巡检周期值不再提交：定时 worker 已下线，巡检由用户点「立即巡检」触发。
      // 真实请求连续失败到这么多次，就把该出口 IP 放进异常池等复验。
      runtime_fail_threshold: Math.max(1, Math.min(100, Number(runtimeFailThreshold.value) || 3)),
      proxy_enabled: proxyEnabled.value,
      // 单 IP「验证健康」的探测模型属于 scan 段（后端 `OpenCodeScanConfig` 读这里）。
      probe_model: probeModel.value.trim() || 'big-pickle',
      // 健康维护是独立的一段，不能塞进 opencode_scan —— 后者会把它当成未知字段丢掉。
      opencode_health: {
        min_pool_size: Math.max(1, Number(minPoolSize.value) || 5),
        session_sticky_enabled: sessionStickyEnabled.value,
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

function isVerifyingIp(ip: string): boolean {
  return verifyingIps.value.has(ip)
}

/** 行内结论的颜色：通过绿、未通过琥珀、限额灰、请求失败红。 */
function verifyBadgeToneClass(tone: VerifyBadgeTone): string {
  if (tone === 'ok') return 'text-emerald-600'
  if (tone === 'quota') return 'text-muted-foreground'
  if (tone === 'error') return 'text-destructive'
  return 'text-amber-600'
}

/** 行内按钮的悬停说明 + 最近一次结论（完整文案，含 median_ms / reason）。 */
function verifyCellTitle(ip: string): string {
  const last = verifyIpMessages.value[ip]
  const base = legacyT('对该 IP 发一次真实 chat 探测：通过即清掉异常计数，失败则记入异常池')
  return last ? `${base}\n${last}` : base
}

/**
 * 验证**单个** IP 的健康：一次真实 chat 探测（成本 = 一个请求）。
 *
 * 结果按后台维护 worker 的同一套账本落账：200 清计数、403/429 不算不可达、
 * 其它失败计数 +1。提示就近显示在该行（行内 toast 会盖住表格，得不偿失）。
 */
async function handleVerifyIp(ip: string) {
  if (verifyingIps.value.has(ip)) return
  verifyingIps.value = new Set(verifyingIps.value).add(ip)
  // 上一次的结论不能和这一轮的 spinner 并排显示：那是另一个时间点的结果。
  delete verifyIpBadges.value[ip]
  errorMessage.value = null
  try {
    const result = await verifyOpenCodeExitIp(props.provider.id, ip)
    // 弹窗展示这次探测真实发出的请求与收到的响应原文（后端 `trace` 字段）。
    // 健康 / 限额 / 失败三种结论都要弹：要看的正是上游原样的往返内容，
    // 而不只是行内那枚结论徽标。
    verifyTraceResult.value = {
      ip: result.ip,
      healthy: result.healthy,
      quota_limited: result.quota_limited,
      reason: result.reason ?? null,
      median_ms: result.median_ms ?? null,
      fails: result.fails,
      trace: result.trace,
    }
    verifyTraceOpen.value = true
    if (result.healthy) {
      const median = Number(result.median_ms)
      verifyIpBadges.value[ip] = {
        tone: 'ok',
        text: `✓ ${Number.isFinite(median) && median > 0 ? `${Math.round(median)}ms` : '-'}`,
      }
      verifyIpMessages.value[ip] = legacyT(
        `通过（${result.median_ms ?? '-'} ms），异常计数已清零`,
      )
    } else if (result.quota_limited) {
      verifyIpBadges.value[ip] = { tone: 'quota', text: legacyT('限额') }
      verifyIpMessages.value[ip] = legacyT('额度受限（403/429）：不计不可达，也不清计数')
    } else {
      const fails = Number(result.fails)
      // 失败次数缺失时退化成 `-`：绝不显示 `undefined` 或 `NaN 次`。
      const suffix =
        Number.isFinite(fails) && fails > 0 ? `${Math.floor(fails)} 次` : '-'
      verifyIpBadges.value[ip] = { tone: 'fail', text: legacyT(`✗ ${suffix}`) }
      verifyIpMessages.value[ip] = legacyT(
        `未通过（${result.reason ?? 'unreachable'}），累计失败 ${result.fails} 次`,
      )
    }
    await loadStatus()
    emit('refresh')
  } catch (err) {
    verifyIpBadges.value[ip] = { tone: 'error', text: legacyT('错误') }
    verifyIpMessages.value[ip] = legacyT(`验证失败：${getErrorMessage(err)}`)
  } finally {
    const next = new Set(verifyingIps.value)
    next.delete(ip)
    verifyingIps.value = next
  }
}

/**
 * 手工加一个出口 IP。
 *
 * 池模型只剩一种（provider 级四态池），服务端 `pool_source` 恒为 `provider`，
 * 所以这里不再按 pool_source 分叉去改 key 自带的出口 IP。
 */
async function handleAddIp() {
  const ip = normalizeIp(newIpInput.value)
  if (!ip) {
    errorMessage.value = legacyT(`无效 IP：${newIpInput.value.trim()}`)
    return
  }
  if (poolHasIp(ip)) {
    errorMessage.value = legacyT(`IP ${ip} 已在池中`)
    return
  }
  busy.value = true
  errorMessage.value = null
  try {
    // 池模型只剩一种：手工加 IP 也进 provider 级池（以前 key 模式那条会顺手建一条
    // 自带出口 IP 的 key，已随「一 key 一 IP」模型删除）。加完还要靠复验才会转为可用。
    await addOpenCodeExitIp(props.provider.id, ip)
    newIpInput.value = ''
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`添加 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

/**
 * 立即巡检：手动跑一轮「全池 TLS + `GET /` 零额度探针」。
 *
 * 后台维护 worker 已下线，这是唯一会让池子自己变好的入口。它同时承担
 * 「连续失败进异常 / 累计到阈值剔除」，所以成功之后必须重新拉一次状态，
 * 否则表格还停在巡检前的样子，看着像什么都没发生。
 */
async function handleRunMaintenance() {
  if (inspecting.value) return
  inspecting.value = true
  errorMessage.value = null
  try {
    const result = await runOpenCodeIpPoolMaintenance(props.provider.id)
    const seconds = (Number(result.elapsed_ms || 0) / 1000).toFixed(1)
    showSuccess(
      legacyT(
        `巡检完成：探测 ${result.checked}，不可达 ${result.unreachable}，剔除 ${result.evicted}，异常池 ${result.abnormal_total}，用时 ${seconds}s`,
      ),
    )
    await loadStatus()
    emit('refresh')
  } catch (err) {
    // 两条通道都给：toast 在按钮旁边当场可见，常驻错误条留证据。
    // 面板很长，只在底部写一行等于「点了没反应」。
    const detail = legacyT(`巡检失败：${getErrorMessage(err)}`)
    errorMessage.value = detail
    showError(detail)
  } finally {
    inspecting.value = false
  }
}

/**
 * 停用 / 启用单个出口 IP。
 *
 * 停用是「留在池里但请求路径跳过它」，与删除不同：可逆，且池子总数不变。
 * `disabled` 就是 `exit_pool_disabled` 的成员关系，所以取反即可。
 */
async function handleToggleIp(ip: string, disabled: boolean) {
  busy.value = true
  errorMessage.value = null
  try {
    // 参数是**目标状态**：当前已停用就传 true（启用），否则传 false（停用）。
    await toggleOpenCodeExitIp(props.provider.id, ip, disabled)
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(
      `${disabled ? '启用' : '停用'} IP 失败：${getErrorMessage(err)}`,
    )
  } finally {
    busy.value = false
  }
}

/**
 * 从出口池里删除一个 IP。
 *
 * 必须二次确认：池子纯手动维护，删掉只能靠人手输回来，手滑一次就是一次停摆。
 * 确认交互沿用全局 ConfirmContainer（与供应商详情里的删除同款），不另造一套。
 */
async function handleDeleteIp(ip: string) {
  const confirmed = await confirm({
    title: legacyT('删除出口 IP'),
    message: legacyT(
      `确定把 ${ip} 从出口池里删除吗？删除后它不再参与轮转，要恢复只能手动重新添加。`,
    ),
    confirmText: legacyT('删除'),
    cancelText: legacyT('取消'),
    variant: 'danger',
  })
  if (!confirmed) return
  busy.value = true
  errorMessage.value = null
  try {
    await removeOpenCodeExitIp(props.provider.id, ip)
    // 顺手清掉这个 IP 的旧验证结论：它可能被重新加回来，那时不该带着上一轮的结果。
    delete verifyIpBadges.value[ip]
    delete verifyIpMessages.value[ip]
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`删除 IP 失败：${getErrorMessage(err)}`)
  } finally {
    busy.value = false
  }
}

/**
 * 拉黑：别用它。
 *
 * 只写 `blocked`，不动 `healthy` / `exit_pool`——拉黑的信息量比删除大得多，
 * 而且一条命令就能解禁。
 */
async function handleBlockIp(ip: string) {
  busy.value = true
  errorMessage.value = null
  try {
    await blockOpenCodeExitIp(props.provider.id, ip)
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`拉黑 IP 失败：${err}`)
  } finally {
    busy.value = false
  }
}

/** 解除拉黑。 */
async function handleUnblockIp(ip: string) {
  busy.value = true
  errorMessage.value = null
  try {
    await unblockOpenCodeExitIp(props.provider.id, ip)
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`解除拉黑失败：${err}`)
  } finally {
    busy.value = false
  }
}

/**
 * 一键重置异常池，同时清掉可用池骤缩告警。
 *
 * 这条路径的典型用法是：告警说池子砍半了，人判断「是我们自己的探针坏了」，
 * 于是清空异常池（拉黑是人工决定，不在这里的语义里）。
 */
async function handleResetAbnormal() {
  busy.value = true
  errorMessage.value = null
  try {
    await resetOpenCodeAbnormalIps(props.provider.id)
    await loadStatus()
    emit('refresh')
  } catch (err) {
    errorMessage.value = legacyT(`重置异常池失败：${err}`)
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
