<template>
  <Dialog
    :model-value="modelValue"
    title="高级设置"
    description="冷却、热池与其他高级参数"
    size="3xl"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="max-h-[calc(100dvh-13rem)] space-y-5 overflow-y-auto overscroll-contain pr-1 sm:max-h-[min(72vh,42rem)] sm:space-y-6 sm:pr-2">
      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              冷却与热池
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              核心策略
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            控制冷却时间、自适应热池和异常清理。
          </p>
        </div>

        <div class="grid gap-3 lg:grid-cols-2">
          <div
            v-for="item in healthToggleCards"
            :key="item.key"
            class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between lg:items-center"
          >
            <div class="min-w-0 flex-1 space-y-1">
              <div class="flex items-center gap-1.5">
                <span class="text-sm font-medium">{{ item.label }}</span>
                <TooltipProvider
                  :delay-duration="100"
                >
                  <Tooltip>
                    <TooltipTrigger as-child>
                      <button
                        type="button"
                        :title="item.description"
                        :aria-label="`${item.label} 说明`"
                        class="hidden lg:inline-flex items-center justify-center rounded-sm p-0.5 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
                      >
                        <CircleHelp class="h-3.5 w-3.5" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent
                      side="top"
                      :side-offset="8"
                      class="max-w-xs px-3 py-2 text-xs leading-5"
                    >
                      {{ item.description }}
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
              <p class="text-xs leading-5 text-muted-foreground lg:hidden">
                {{ item.description }}
              </p>
            </div>
            <Switch
              :model-value="getHealthToggleValue(item.key)"
              class="shrink-0"
              @update:model-value="(v: boolean) => updateHealthToggleValue(item.key, v)"
            />
          </div>
        </div>

        <div
          v-if="form.account_self_check_enabled"
          class="space-y-3 rounded-xl border border-dashed border-primary/25 bg-primary/5 p-4"
        >
          <div class="grid gap-3 sm:grid-cols-2">
            <div class="space-y-1.5">
              <Label>
                自检间隔
                <span class="text-xs text-muted-foreground">(分钟)</span>
              </Label>
              <Input
                :model-value="form.account_self_check_interval_minutes ?? ''"
                type="number"
                min="1"
                max="1440"
                placeholder="60"
                @update:model-value="(v) => form.account_self_check_interval_minutes = parseNum(v)"
              />
            </div>
            <div class="space-y-1.5">
              <Label>
                自检并发
              </Label>
              <Input
                :model-value="form.account_self_check_concurrency ?? ''"
                type="number"
                min="1"
                max="64"
                placeholder="4"
                @update:model-value="(v) => form.account_self_check_concurrency = parseNum(v)"
              />
            </div>
          </div>
        </div>

        <div
          class="grid gap-3 sm:grid-cols-2"
          :class="cooldownFieldLayout.desktopColumnsClass"
        >
          <div class="space-y-1.5">
            <Label>
              429 冷却
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.rate_limit_cooldown_seconds ?? ''"
              type="number"
              min="10"
              max="3600"
              placeholder="300"
              @update:model-value="(v) => form.rate_limit_cooldown_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              529 冷却
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.overload_cooldown_seconds ?? ''"
              type="number"
              min="5"
              max="600"
              placeholder="30"
              @update:model-value="(v) => form.overload_cooldown_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              429 冷却上限
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.rate_limit_cooldown_max_seconds ?? ''"
              type="number"
              min="0"
              step="60"
              placeholder="7200"
              @update:model-value="(v) => form.rate_limit_cooldown_max_seconds = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              连续 429（且上游没给 Retry-After）时，429 冷却逐次翻倍到此上限；填 0 或小于基础冷却 = 关闭退避。
            </p>
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              熔断与风控
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              WorkBuddy
            </span>
          </div>
        </div>
        <div class="flex items-start justify-between gap-4">
          <div class="space-y-1">
            <Label>
              WAF 拦截期连新请求一起挡
            </Label>
            <p class="text-[11px] leading-5 text-muted-foreground">
              关闭 = 完全对齐面板（只停本次请求的轮转；账号级软冷却仍在，同一账号不会被反复重试）。
            </p>
          </div>
          <Switch
            :model-value="form.waf_ip_block_new_requests"
            class="shrink-0"
            @update:model-value="(v: boolean) => form.waf_ip_block_new_requests = v"
          />
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>
              WAF 拦截窗口
              <span class="text-xs text-muted-foreground">(秒，默认 60，0 = 关停)</span>
            </Label>
            <Input
              :model-value="form.waf_ip_cooldown_seconds ?? ''"
              type="number"
              min="0"
              step="10"
              placeholder="60"
              @update:model-value="(v) => form.waf_ip_cooldown_seconds = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              滑动窗与激活时长同值（面板口径）；填 0 = 整项关停。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              积分保底
              <span class="text-xs text-muted-foreground">(0 = 关闭)</span>
            </Label>
            <Input
              :model-value="form.credit_floor ?? ''"
              type="number"
              min="0"
              step="100"
              placeholder="0"
              @update:model-value="(v) => form.credit_floor = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              余额**低于**该值的账号不接收费模型（免费模型照常走）。
            </p>
          </div>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>
              熔断阈值
              <span class="text-xs text-muted-foreground">(连续失败次数，默认 3)</span>
            </Label>
            <Input
              :model-value="form.breaker_threshold ?? ''"
              type="number"
              min="1"
              :placeholder="String(POOL_ADVANCED_DEFAULTS.breakerThreshold)"
              @update:model-value="(v) => form.breaker_threshold = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              连续失败达到该次数即熔断；留空 = 用默认值 {{ POOL_ADVANCED_DEFAULTS.breakerThreshold }}。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              熔断基础时长
              <span class="text-xs text-muted-foreground">(分钟，默认 30)</span>
            </Label>
            <Input
              :model-value="form.breaker_cooldown_minutes ?? ''"
              type="number"
              min="0"
              step="5"
              :placeholder="String(POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes)"
              @update:model-value="(v) => form.breaker_cooldown_minutes = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              熔断后基础冷却时长（默认 {{ POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes }} 分钟）；
              填 0 = 沿用 Aether 历史值（1 分钟）。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              熔断退避上限
              <span class="text-xs text-muted-foreground">(分钟，默认 360 = 6h)</span>
            </Label>
            <Input
              :model-value="form.breaker_cooldown_max_minutes ?? ''"
              type="number"
              min="0"
              step="30"
              :placeholder="String(POOL_ADVANCED_DEFAULTS.breakerCooldownMaxMinutes)"
              @update:model-value="(v) => form.breaker_cooldown_max_minutes = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              连续失败按 2 的幂退避到此上限（默认 {{ POOL_ADVANCED_DEFAULTS.breakerCooldownMaxMinutes }} 分钟 = 6h，另有 24h 安全天花板）；
              填 0 = 沿用历史 32 分钟。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              单账号最大在途
              <span class="text-xs text-muted-foreground">(并发，默认 3，0 = 不分档)</span>
            </Label>
            <Input
              :model-value="form.max_in_flight ?? ''"
              type="number"
              min="0"
              :max="POOL_ADVANCED_MAX_IN_FLIGHT"
              :placeholder="String(POOL_ADVANCED_DEFAULTS.maxInFlight)"
              @update:model-value="(v) => form.max_in_flight = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              **所有账号**的在途兜底档（默认 {{ POOL_ADVANCED_DEFAULTS.maxInFlight }}，国际号被下面的分档压得更低）；
              填 0 = 回落账号自身上限（不分档）。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              成本探索窗口
              <span class="text-xs text-muted-foreground">(秒，默认 1800，0 = 关停)</span>
            </Label>
            <Input
              :model-value="form.cost_explore_interval_seconds ?? ''"
              type="number"
              min="0"
              step="60"
              :placeholder="String(POOL_ADVANCED_DEFAULTS.costExploreIntervalSeconds)"
              @update:model-value="(v) => form.cost_explore_interval_seconds = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              当前最优是「已观测免费」档时，每隔该窗口改选一次**未观测**的账号去探路（默认
              {{ POOL_ADVANCED_DEFAULTS.costExploreIntervalSeconds }} 秒 = 30 分钟）；填 0 = 关停。
            </p>
          </div>
        </div>
        <div class="flex items-start justify-between gap-4">
          <div class="space-y-1">
            <Label>
              池内账号也计入熔断
            </Label>
            <p class="text-[11px] leading-5 text-muted-foreground">
              面板口径：池就是全量账号，熔断对所有账号生效；本系统默认只降健康分（行为不变）。
            </p>
          </div>
          <Switch
            :model-value="form.pool_counts_toward_circuit_breaker"
            class="shrink-0"
            @update:model-value="(v: boolean) => form.pool_counts_toward_circuit_breaker = v"
          />
        </div>
        <div class="space-y-1 border-t border-border/40 pt-3">
          <h4 class="text-xs font-semibold text-muted-foreground">
            延迟与成本统计窗口
          </h4>
          <p class="text-[11px] leading-5 text-muted-foreground">
            选号打分里「延迟 / 成本」两个维度用多长的窗口、采多少样本 —— 一般不用动。
          </p>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>
              延迟统计窗口
              <span class="text-xs text-muted-foreground">(秒，默认 3600)</span>
            </Label>
            <Input
              :model-value="form.latency_window_seconds ?? ''"
              type="number"
              min="60"
              step="600"
              placeholder="3600"
              @update:model-value="(v) => form.latency_window_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              延迟采样条数
              <span class="text-xs text-muted-foreground">(默认 50)</span>
            </Label>
            <Input
              :model-value="form.latency_sample_limit ?? ''"
              type="number"
              min="5"
              step="5"
              placeholder="50"
              @update:model-value="(v) => form.latency_sample_limit = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              成本统计窗口
              <span class="text-xs text-muted-foreground">(秒，默认 18000)</span>
            </Label>
            <Input
              :model-value="form.cost_window_seconds ?? ''"
              type="number"
              min="300"
              step="1800"
              placeholder="18000"
              @update:model-value="(v) => form.cost_window_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              单号成本上限
              <span class="text-xs text-muted-foreground">(窗口内 token 数，空 = 不限)</span>
            </Label>
            <Input
              :model-value="form.cost_limit_per_key_tokens ?? ''"
              type="number"
              min="0"
              step="1000"
              placeholder="不限"
              @update:model-value="(v) => form.cost_limit_per_key_tokens = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              快过期积分
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              温和偏好
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            开启后，账号在「窗口内即将到期」的积分越多越容易被选中——目的是尽量早地把要过期的积分用掉，
            属于温和加分而不是硬优先（面板同款语义）。窗口填 0 = 关闭分桶。
          </p>
        </div>
        <div class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between">
          <div class="space-y-1">
            <span class="text-sm font-medium">快过期优先路由</span>
            <p class="text-xs leading-5 text-muted-foreground">
              关闭时窗口照算（卡片仍能展示到期信息），但选号不加分。
            </p>
          </div>
          <Switch
            :model-value="form.prefer_expiring"
            class="shrink-0"
            @update:model-value="(v: boolean) => form.prefer_expiring = v"
          />
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>
              快过期窗口
              <span class="text-xs text-muted-foreground">(秒，默认 604800 = 7 天)</span>
            </Label>
            <Input
              :model-value="form.expiring_soon_seconds ?? ''"
              type="number"
              min="0"
              step="3600"
              placeholder="604800"
              @update:model-value="(v) => form.expiring_soon_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              快过期加分
              <span class="text-xs text-muted-foreground">(0–1，默认 0.10)</span>
            </Label>
            <Input
              :model-value="form.expiring_credit_bonus ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.10"
              @update:model-value="(v) => form.expiring_credit_bonus = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              连败降权
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              未分类错误
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            同一账号连续出现「未分类错误」（既不是 401/402/403/400，也不是 429/529/5xx 等已分类错误）达阈值后临时出池；
            重复连败按 2 的幂延长到上限为止。阈值填 0 = 关闭。
          </p>
        </div>
        <div class="grid gap-3 sm:grid-cols-3">
          <div class="space-y-1.5">
            <Label>
              连败阈值
              <span class="text-xs text-muted-foreground">(次)</span>
            </Label>
            <Input
              :model-value="form.request_demote_threshold ?? ''"
              type="number"
              min="0"
              step="1"
              placeholder="5"
              @update:model-value="(v) => form.request_demote_threshold = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              降权时长
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.request_demote_seconds ?? ''"
              type="number"
              min="1"
              step="60"
              placeholder="600"
              @update:model-value="(v) => form.request_demote_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              降权上限
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.request_demote_max_seconds ?? ''"
              type="number"
              min="1"
              step="60"
              placeholder="7200"
              @update:model-value="(v) => form.request_demote_max_seconds = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              会话粘性
            </h3>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            调度策略含「粘性」维度时生效：同一会话在 TTL 内固定路由到同一账号（账号遇冷却立即重新分配）；0 = 关闭。
          </p>
        </div>
        <div class="grid gap-3 sm:grid-cols-2">
          <div class="space-y-1.5">
            <Label>
              粘性 TTL
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.sticky_session_ttl_seconds ?? ''"
              type="number"
              min="0"
              step="60"
              placeholder="3600"
              @update:model-value="(v) => form.sticky_session_ttl_seconds = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              批量操作
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              任务效率
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            控制刷新 OAuth、自适应热池和批量额度处理时的并行请求数。
          </p>
        </div>

        <div class="grid gap-3 rounded-xl bg-muted/30 p-4 sm:grid-cols-2 xl:grid-cols-4">
          <div class="space-y-1.5">
            <Label>
              并发数
            </Label>
            <Input
              :model-value="form.batch_concurrency ?? ''"
              type="number"
              min="1"
              max="32"
              placeholder="8"
              @update:model-value="(v) => form.batch_concurrency = parseNum(v)"
            />
            <p class="text-[11px] leading-5 text-muted-foreground">
              为空时沿用默认值；数值越大，批量操作越快，但会增加瞬时请求压力。
            </p>
          </div>
          <div class="space-y-1.5">
            <Label>
              探测并发
            </Label>
            <Input
              :model-value="form.probe_concurrency ?? ''"
              type="number"
              min="1"
              max="64"
              placeholder="4"
              @update:model-value="(v) => form.probe_concurrency = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              评分 Top-N
            </Label>
            <Input
              :model-value="form.score_top_n ?? ''"
              type="number"
              min="1"
              max="4096"
              placeholder="128"
              @update:model-value="(v) => form.score_top_n = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>
              回退扫描
            </Label>
            <Input
              :model-value="form.score_fallback_scan_limit ?? ''"
              type="number"
              min="1"
              max="100000"
              placeholder="1024"
              @update:model-value="(v) => form.score_fallback_scan_limit = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5">
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              分数规则
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              候选排序
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            调整探测结果、健康、额度、延迟和使用成本进入号池候选排序时的权重。
          </p>
        </div>

        <div class="grid gap-3 lg:grid-cols-3">
          <div class="space-y-1.5">
            <Label>优先级权重</Label>
            <Input
              :model-value="form.score_weight_manual_priority ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.30"
              @update:model-value="(v) => form.score_weight_manual_priority = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>健康权重</Label>
            <Input
              :model-value="form.score_weight_health ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.20"
              @update:model-value="(v) => form.score_weight_health = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>探测新鲜度权重</Label>
            <Input
              :model-value="form.score_weight_probe_freshness ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.15"
              @update:model-value="(v) => form.score_weight_probe_freshness = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>额度剩余权重</Label>
            <Input
              :model-value="form.score_weight_quota_remaining ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.15"
              @update:model-value="(v) => form.score_weight_quota_remaining = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>延迟权重</Label>
            <Input
              :model-value="form.score_weight_latency ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.10"
              @update:model-value="(v) => form.score_weight_latency = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>成本/LRU 权重</Label>
            <Input
              :model-value="form.score_weight_cost_lru ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.10"
              @update:model-value="(v) => form.score_weight_cost_lru = parseNum(v)"
            />
          </div>
        </div>

        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div class="space-y-1.5">
            <Label>
              探测新鲜度 TTL
              <span class="text-xs text-muted-foreground">(秒)</span>
            </Label>
            <Input
              :model-value="form.probe_freshness_ttl_seconds ?? ''"
              type="number"
              min="1"
              max="604800"
              placeholder="1800"
              @update:model-value="(v) => form.probe_freshness_ttl_seconds = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>探测失败惩罚</Label>
            <Input
              :model-value="form.probe_failure_penalty ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.05"
              @update:model-value="(v) => form.probe_failure_penalty = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>请求失败惩罚</Label>
            <Input
              :model-value="form.request_failure_penalty ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.001"
              placeholder="0.005"
              @update:model-value="(v) => form.request_failure_penalty = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>探测失败冷却阈值</Label>
            <Input
              :model-value="form.probe_failure_cooldown_threshold ?? ''"
              type="number"
              min="0"
              max="100"
              placeholder="3"
              @update:model-value="(v) => form.probe_failure_cooldown_threshold = parseNum(v)"
            />
          </div>
          <div class="space-y-1.5">
            <Label>不可调度分数上限</Label>
            <Input
              :model-value="form.unschedulable_score_cap ?? ''"
              type="number"
              min="0"
              max="1"
              step="0.01"
              placeholder="0.05"
              @update:model-value="(v) => form.unschedulable_score_cap = parseNum(v)"
            />
          </div>
        </div>
      </section>

      <section
        v-if="isClaudeCode"
        class="space-y-4 rounded-2xl border border-border/60 bg-card/70 p-4 sm:p-5"
      >
        <div class="space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-sm font-semibold">
              Claude Code
            </h3>
            <span class="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">
              请求约束
            </span>
          </div>
          <p class="text-xs leading-5 text-muted-foreground">
            管理 CLI 请求限制、会话控制和 metadata / cache 相关的兼容行为。
          </p>
        </div>

        <div class="grid gap-3 lg:grid-cols-2">
          <div class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
              <span class="text-sm font-medium">Session ID 伪装</span>
              <p class="text-xs leading-5 text-muted-foreground">
                固定 metadata.user_id 中 session 片段。
              </p>
            </div>
            <Switch
              :model-value="claudeForm.session_id_masking_enabled"
              class="shrink-0"
              @update:model-value="(v: boolean) => claudeForm.session_id_masking_enabled = v"
            />
          </div>

          <div class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
              <span class="text-sm font-medium">仅限 CLI 客户端</span>
              <p class="text-xs leading-5 text-muted-foreground">
                仅允许 Claude Code CLI 格式请求。
              </p>
            </div>
            <Switch
              :model-value="claudeForm.cli_only_enabled"
              class="shrink-0"
              @update:model-value="(v: boolean) => claudeForm.cli_only_enabled = v"
            />
          </div>

          <div class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
              <span class="text-sm font-medium">Cache TTL 统一</span>
              <p class="text-xs leading-5 text-muted-foreground">
                强制所有 cache_control 使用同一种 TTL 类型。
              </p>
            </div>
            <Switch
              :model-value="claudeForm.cache_ttl_override_enabled"
              class="shrink-0"
              @update:model-value="(v: boolean) => claudeForm.cache_ttl_override_enabled = v"
            />
          </div>

          <div class="flex flex-col gap-3 rounded-xl border border-border/60 bg-muted/30 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
              <span class="text-sm font-medium">会话数量控制</span>
              <p class="text-xs leading-5 text-muted-foreground">
                限制单 Key 同时活跃会话数，降低长期占用风险。
              </p>
            </div>
            <Switch
              :model-value="claudeForm.session_control_enabled"
              class="shrink-0"
              @update:model-value="(v: boolean) => claudeForm.session_control_enabled = v"
            />
          </div>
        </div>

        <div
          v-if="claudeForm.cache_ttl_override_enabled"
          class="rounded-xl border border-dashed border-primary/25 bg-primary/5 p-4"
        >
          <div class="space-y-1.5">
            <Label>TTL 类型</Label>
            <div class="flex w-fit gap-0.5 rounded-md bg-muted/40 p-0.5">
              <button
                v-for="opt in ['ephemeral']"
                :key="opt"
                type="button"
                class="rounded px-2.5 py-1 text-xs font-medium transition-all"
                :class="[
                  claudeForm.cache_ttl_override_target === opt
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:bg-background/50 hover:text-foreground'
                ]"
                @click="claudeForm.cache_ttl_override_target = opt"
              >
                {{ opt }}
              </button>
            </div>
          </div>
        </div>

        <div
          v-if="claudeForm.session_control_enabled"
          class="rounded-xl border border-dashed border-primary/25 bg-primary/5 p-4"
        >
          <div class="grid gap-3 sm:grid-cols-2">
            <div class="space-y-1.5">
              <Label>
                最大会话数
              </Label>
              <Input
                :model-value="claudeForm.max_sessions ?? ''"
                type="number"
                min="1"
                max="100"
                placeholder="留空 = 不限"
                @update:model-value="(v) => claudeForm.max_sessions = parseNum(v)"
              />
            </div>
            <div class="space-y-1.5">
              <Label>
                空闲超时
                <span class="text-xs text-muted-foreground">(分钟)</span>
              </Label>
              <Input
                :model-value="claudeForm.session_idle_timeout_minutes ?? ''"
                type="number"
                min="1"
                max="1440"
                placeholder="5"
                @update:model-value="(v) => claudeForm.session_idle_timeout_minutes = parseNum(v) ?? 5"
              />
            </div>
          </div>
        </div>
      </section>
    </div>

    <template #footer>
      <Button
        variant="outline"
        class="min-w-[96px] flex-1 sm:flex-none"
        :disabled="loading"
        @click="emit('update:modelValue', false)"
      >
        取消
      </Button>
      <Button
        class="min-w-[96px] flex-1 sm:flex-none"
        :disabled="loading"
        @click="handleSave"
      >
        {{ loading ? '保存中...' : '保存' }}
      </Button>
    </template>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CircleHelp } from 'lucide-vue-next'
import { Dialog, Button, Input, Label, Switch, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui'
import { useToast } from '@/composables/useToast'
import { parseApiError } from '@/utils/errorParser'
import { getProvider, updateProvider } from '@/api/endpoints'
import { mergePoolAdvancedPatch } from '@/features/pool/utils/poolSchedulingDialog'
import {
  POOL_ADVANCED_DEFAULTS,
  POOL_ADVANCED_MAX_IN_FLIGHT,
} from '@/features/pool/utils/poolAdvancedDefaults'
import {
  buildPoolCooldownFieldLayout,
  buildPoolHealthToggleCards,
  type PoolHealthToggleKey,
} from '@/features/pool/utils/poolAdvancedDialog'
import type {
  PoolAdvancedConfig,
  ClaudeCodeAdvancedConfig,
  ProviderWithEndpointsSummary,
} from '@/api/endpoints/types/provider'

const props = defineProps<{
  modelValue: boolean
  providerId: string
  providerType?: string
  currentConfig: PoolAdvancedConfig | null
  currentClaudeConfig?: ClaudeCodeAdvancedConfig | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  saved: [provider: ProviderWithEndpointsSummary]
}>()

const { success, error: showError } = useToast()
const loading = ref(false)
let dialogRevision = 0

const isClaudeCode = computed(() => {
  return (props.providerType || '').trim().toLowerCase() === 'claude_code'
})

const healthToggleCards = buildPoolHealthToggleCards()
const cooldownFieldLayout = buildPoolCooldownFieldLayout()

const form = ref({
  rate_limit_cooldown_seconds: null as number | null | undefined,
  rate_limit_cooldown_max_seconds: null as number | null | undefined,
  overload_cooldown_seconds: null as number | null | undefined,
  sticky_session_ttl_seconds: null as number | null | undefined,
  request_demote_threshold: null as number | null | undefined,
  request_demote_seconds: null as number | null | undefined,
  request_demote_max_seconds: null as number | null | undefined,
  prefer_expiring: true,
  expiring_soon_seconds: null as number | null | undefined,
  expiring_credit_bonus: null as number | null | undefined,
  batch_concurrency: null as number | null | undefined,
  probe_concurrency: null as number | null | undefined,
  score_top_n: null as number | null | undefined,
  score_fallback_scan_limit: null as number | null | undefined,
  score_weight_manual_priority: null as number | null | undefined,
  score_weight_health: null as number | null | undefined,
  score_weight_probe_freshness: null as number | null | undefined,
  score_weight_quota_remaining: null as number | null | undefined,
  score_weight_latency: null as number | null | undefined,
  score_weight_cost_lru: null as number | null | undefined,
  probe_freshness_ttl_seconds: null as number | null | undefined,
  unschedulable_score_cap: null as number | null | undefined,
  probe_failure_penalty: null as number | null | undefined,
  request_failure_penalty: null as number | null | undefined,
  probe_failure_cooldown_threshold: null as number | null | undefined,
  probing_enabled: false,
  account_self_check_enabled: false,
  account_self_check_interval_minutes: null as number | null | undefined,
  account_self_check_concurrency: null as number | null | undefined,
  auto_remove_banned_keys: false,
  auto_remove_quota_exhausted_keys: false,
  ignore_exhausted_accounts: false,
  credit_floor: null as number | null | undefined,
  pool_counts_toward_circuit_breaker: false,
  breaker_threshold: null as number | null | undefined,
  breaker_cooldown_minutes: null as number | null | undefined,
  breaker_cooldown_max_minutes: null as number | null | undefined,
  max_in_flight: null as number | null | undefined,
  cost_explore_interval_seconds: null as number | null | undefined,
  latency_window_seconds: null as number | null | undefined,
  latency_sample_limit: null as number | null | undefined,
  cost_window_seconds: null as number | null | undefined,
  cost_limit_per_key_tokens: null as number | null | undefined,
  waf_ip_cooldown_seconds: 60 as number | null | undefined,
  waf_ip_block_new_requests: true,
})

interface ClaudeFormState {
  session_control_enabled: boolean
  max_sessions: number | undefined
  session_idle_timeout_minutes: number
  session_id_masking_enabled: boolean
  cache_ttl_override_enabled: boolean
  cache_ttl_override_target: string
  cli_only_enabled: boolean
}

const claudeForm = ref<ClaudeFormState>({
  session_control_enabled: true,
  max_sessions: undefined,
  session_idle_timeout_minutes: 5,
  session_id_masking_enabled: true,
  cache_ttl_override_enabled: false,
  cache_ttl_override_target: 'ephemeral',
  cli_only_enabled: false,
})

function parseNum(v: string | number): number | undefined {
  if (v === '' || v === null || v === undefined) return undefined
  const n = Number(v)
  return Number.isNaN(n) ? undefined : n
}

function getHealthToggleValue(key: PoolHealthToggleKey): boolean {
  switch (key) {
    case 'probing_enabled':
      return form.value.probing_enabled
    case 'account_self_check_enabled':
      return form.value.account_self_check_enabled
    case 'auto_remove_banned_keys':
      return form.value.auto_remove_banned_keys
    case 'auto_remove_quota_exhausted_keys':
      return form.value.auto_remove_quota_exhausted_keys
    case 'ignore_exhausted_accounts':
      return form.value.ignore_exhausted_accounts
  }
}

function updateHealthToggleValue(key: PoolHealthToggleKey, value: boolean): void {
  switch (key) {
    case 'probing_enabled':
      form.value.probing_enabled = value
      return
    case 'account_self_check_enabled':
      form.value.account_self_check_enabled = value
      return
    case 'auto_remove_banned_keys':
      form.value.auto_remove_banned_keys = value
      return
    case 'auto_remove_quota_exhausted_keys':
      form.value.auto_remove_quota_exhausted_keys = value
      return
    case 'ignore_exhausted_accounts':
      form.value.ignore_exhausted_accounts = value
  }
}

watch([() => props.modelValue, () => props.providerId], ([open]) => {
  dialogRevision += 1
  loading.value = false
  if (!open) return

  const cfg = props.currentConfig
  const scoreRules = cfg?.score_rules
  const scoreWeights = scoreRules?.weights
  form.value = {
    rate_limit_cooldown_seconds: cfg?.rate_limit_cooldown_seconds ?? null,
    rate_limit_cooldown_max_seconds: cfg?.rate_limit_cooldown_max_seconds ?? null,
    overload_cooldown_seconds: cfg?.overload_cooldown_seconds ?? null,
    credit_floor: cfg?.credit_floor ?? 0,
    pool_counts_toward_circuit_breaker: cfg?.pool_counts_toward_circuit_breaker ?? POOL_ADVANCED_DEFAULTS.poolCountsTowardCircuitBreaker,
    breaker_threshold: cfg?.breaker_threshold ?? POOL_ADVANCED_DEFAULTS.breakerThreshold,
    breaker_cooldown_minutes: cfg?.breaker_cooldown_minutes ?? POOL_ADVANCED_DEFAULTS.breakerCooldownMinutes,
    breaker_cooldown_max_minutes: cfg?.breaker_cooldown_max_minutes ?? POOL_ADVANCED_DEFAULTS.breakerCooldownMaxMinutes,
    
    max_in_flight: cfg?.max_in_flight ?? POOL_ADVANCED_DEFAULTS.maxInFlight,
    cost_explore_interval_seconds: cfg?.cost_explore_interval_seconds ?? POOL_ADVANCED_DEFAULTS.costExploreIntervalSeconds,
    latency_window_seconds: cfg?.latency_window_seconds ?? 3600,
    latency_sample_limit: cfg?.latency_sample_limit ?? 50,
    cost_window_seconds: cfg?.cost_window_seconds ?? 18000,
    cost_limit_per_key_tokens: cfg?.cost_limit_per_key_tokens ?? null,
    waf_ip_cooldown_seconds: cfg?.waf_ip_cooldown_seconds ?? POOL_ADVANCED_DEFAULTS.wafIpCooldownSeconds,
    waf_ip_block_new_requests: cfg?.waf_ip_block_new_requests ?? POOL_ADVANCED_DEFAULTS.wafIpBlockNewRequests,
    sticky_session_ttl_seconds: cfg?.sticky_session_ttl_seconds ?? null,
    request_demote_threshold: cfg?.request_demote_threshold ?? null,
    request_demote_seconds: cfg?.request_demote_seconds ?? null,
    request_demote_max_seconds: cfg?.request_demote_max_seconds ?? null,
    prefer_expiring: cfg?.prefer_expiring ?? true,
    expiring_soon_seconds: cfg?.expiring_soon_seconds ?? null,
    expiring_credit_bonus: cfg?.expiring_credit_bonus ?? null,
    batch_concurrency: cfg?.batch_concurrency ?? null,
    probe_concurrency: cfg?.probe_concurrency ?? null,
    score_top_n: cfg?.score_top_n ?? null,
    score_fallback_scan_limit: cfg?.score_fallback_scan_limit ?? null,
    score_weight_manual_priority: scoreWeights?.manual_priority ?? null,
    score_weight_health: scoreWeights?.health ?? null,
    score_weight_probe_freshness: scoreWeights?.probe_freshness ?? null,
    score_weight_quota_remaining: scoreWeights?.quota_remaining ?? null,
    score_weight_latency: scoreWeights?.latency ?? null,
    score_weight_cost_lru: scoreWeights?.cost_lru ?? null,
    probe_freshness_ttl_seconds: scoreRules?.probe_freshness_ttl_seconds ?? null,
    unschedulable_score_cap: scoreRules?.unschedulable_score_cap ?? null,
    probe_failure_penalty: scoreRules?.probe_failure_penalty ?? null,
    request_failure_penalty: scoreRules?.request_failure_penalty ?? null,
    probe_failure_cooldown_threshold: scoreRules?.probe_failure_cooldown_threshold ?? null,
    probing_enabled: cfg?.probing_enabled ?? false,
    account_self_check_enabled: cfg?.account_self_check_enabled ?? false,
    account_self_check_interval_minutes: cfg?.account_self_check_interval_minutes ?? null,
    account_self_check_concurrency: cfg?.account_self_check_concurrency ?? null,
    auto_remove_banned_keys: cfg?.auto_remove_banned_keys ?? false,
    auto_remove_quota_exhausted_keys: cfg?.auto_remove_quota_exhausted_keys ?? false,
    ignore_exhausted_accounts: cfg?.ignore_exhausted_accounts ?? false,
  }

  const cc = props.currentClaudeConfig
  claudeForm.value = {
    session_control_enabled: cc?.max_sessions !== null,
    max_sessions: cc?.max_sessions ?? undefined,
    session_idle_timeout_minutes: cc?.session_idle_timeout_minutes ?? 5,
    session_id_masking_enabled: cc?.session_id_masking_enabled !== false,
    cache_ttl_override_enabled: cc?.cache_ttl_override_enabled ?? false,
    cache_ttl_override_target: cc?.cache_ttl_override_target ?? 'ephemeral',
    cli_only_enabled: cc?.cli_only_enabled ?? false,
  }
})

async function handleSave() {
  const providerId = props.providerId
  const revision = dialogRevision
  loading.value = true
  try {
    const latestProvider = await getProvider(providerId)
    if (!props.modelValue || props.providerId !== providerId || dialogRevision !== revision) return
    const latestAdvanced = latestProvider.pool_advanced
    const existingPoolAdvanced = mergePoolAdvancedPatch(latestAdvanced, {})
    const latestScoreRules = typeof existingPoolAdvanced.score_rules === 'object'
      && existingPoolAdvanced.score_rules !== null
      ? existingPoolAdvanced.score_rules as Record<string, unknown>
      : {}
    const latestScoreWeights = typeof latestScoreRules.weights === 'object'
      && latestScoreRules.weights !== null
      ? latestScoreRules.weights as Record<string, unknown>
      : {}
    const scoreRules = {
      ...latestScoreRules,
      weights: {
        ...latestScoreWeights,
        manual_priority: form.value.score_weight_manual_priority ?? undefined,
        health: form.value.score_weight_health ?? undefined,
        probe_freshness: form.value.score_weight_probe_freshness ?? undefined,
        quota_remaining: form.value.score_weight_quota_remaining ?? undefined,
        latency: form.value.score_weight_latency ?? undefined,
        cost_lru: form.value.score_weight_cost_lru ?? undefined,
      },
      probe_freshness_ttl_seconds: form.value.probe_freshness_ttl_seconds ?? undefined,
      unschedulable_score_cap: form.value.unschedulable_score_cap ?? undefined,
      probe_failure_penalty: form.value.probe_failure_penalty ?? undefined,
      request_failure_penalty: form.value.request_failure_penalty ?? undefined,
      probe_failure_cooldown_threshold: form.value.probe_failure_cooldown_threshold ?? undefined,
    }
    // 合并已有配置（保留 scheduling_presets 等不在此对话框编辑的字段）
    const poolAdvanced = mergePoolAdvancedPatch(existingPoolAdvanced, {
      rate_limit_cooldown_seconds: form.value.rate_limit_cooldown_seconds ?? undefined,
      rate_limit_cooldown_max_seconds: form.value.rate_limit_cooldown_max_seconds ?? undefined,
      overload_cooldown_seconds: form.value.overload_cooldown_seconds ?? undefined,
      credit_floor: form.value.credit_floor ?? undefined,
      pool_counts_toward_circuit_breaker: form.value.pool_counts_toward_circuit_breaker,
      breaker_threshold: form.value.breaker_threshold ?? undefined,
      breaker_cooldown_minutes: form.value.breaker_cooldown_minutes ?? undefined,
      breaker_cooldown_max_minutes: form.value.breaker_cooldown_max_minutes ?? undefined,
      
      max_in_flight: form.value.max_in_flight ?? undefined,
      cost_explore_interval_seconds: form.value.cost_explore_interval_seconds ?? undefined,
      latency_window_seconds: form.value.latency_window_seconds ?? undefined,
      latency_sample_limit: form.value.latency_sample_limit ?? undefined,
      cost_window_seconds: form.value.cost_window_seconds ?? undefined,
      cost_limit_per_key_tokens: form.value.cost_limit_per_key_tokens ?? undefined,
      waf_ip_cooldown_seconds: form.value.waf_ip_cooldown_seconds ?? undefined,
      waf_ip_block_new_requests: form.value.waf_ip_block_new_requests,
      sticky_session_ttl_seconds: form.value.sticky_session_ttl_seconds ?? undefined,
      request_demote_threshold: form.value.request_demote_threshold ?? undefined,
      request_demote_seconds: form.value.request_demote_seconds ?? undefined,
      request_demote_max_seconds: form.value.request_demote_max_seconds ?? undefined,
      prefer_expiring: form.value.prefer_expiring,
      expiring_soon_seconds: form.value.expiring_soon_seconds ?? undefined,
      expiring_credit_bonus: form.value.expiring_credit_bonus ?? undefined,
      batch_concurrency: form.value.batch_concurrency ?? undefined,
      probe_concurrency: form.value.probe_concurrency ?? undefined,
      score_top_n: form.value.score_top_n ?? undefined,
      score_fallback_scan_limit: form.value.score_fallback_scan_limit ?? undefined,
      score_rules: scoreRules,
      probing_enabled: form.value.probing_enabled,
      account_self_check_enabled: form.value.account_self_check_enabled,
      account_self_check_interval_minutes: form.value.account_self_check_enabled
        ? (form.value.account_self_check_interval_minutes ?? undefined)
        : undefined,
      account_self_check_concurrency: form.value.account_self_check_enabled
        ? (form.value.account_self_check_concurrency ?? undefined)
        : undefined,
      auto_remove_banned_keys: form.value.auto_remove_banned_keys,
      auto_remove_quota_exhausted_keys: form.value.auto_remove_quota_exhausted_keys,
      ignore_exhausted_accounts: form.value.ignore_exhausted_accounts,
    })

    const payload: Parameters<typeof updateProvider>[1] = {
      pool_advanced: poolAdvanced as PoolAdvancedConfig,
    }
    if (isClaudeCode.value) {
      const cf = claudeForm.value
      payload.claude_code_advanced = {
        max_sessions: cf.session_control_enabled ? (cf.max_sessions ?? null) : null,
        session_idle_timeout_minutes: cf.session_control_enabled ? cf.session_idle_timeout_minutes : null,
        session_id_masking_enabled: cf.session_id_masking_enabled,
        cache_ttl_override_enabled: cf.cache_ttl_override_enabled,
        cache_ttl_override_target: cf.cache_ttl_override_enabled ? cf.cache_ttl_override_target : undefined,
        cli_only_enabled: cf.cli_only_enabled,
      }
    }
    const updatedProvider = await updateProvider(providerId, payload)
    if (!props.modelValue || props.providerId !== providerId || dialogRevision !== revision) return
    success('高级设置已保存')
    emit('saved', updatedProvider)
    emit('update:modelValue', false)
  } catch (err) {
    showError(parseApiError(err))
  } finally {
    if (dialogRevision === revision) {
      loading.value = false
    }
  }
}
</script>
