use serde_json::Value;

use crate::ai_serving::{
    maybe_build_ai_surface_stream_rewriter, AiSurfaceFinalizeError, AiSurfaceStreamRewriter,
    ResponseHistoryRecord,
};
use crate::GatewayError;

/// 本地流改写器：把上游字节改写成客户端形态。
///
/// 两种来源：
/// - `Surface`：需要跨格式转换时，由格式层提供（原有路径）；
/// - `WorkbuddyDsml`：客户端与上游同为 `openai:chat` 的 WorkBuddy 流。这种流格式层
///   没有改写器可挂（响应直通），但模型可能把工具调用写成内联 `‖DSML‖` 标记，
///   不还原的话执行工具的客户端会把标记当正文收下、回合直接结束。
pub(crate) enum LocalStreamRewriter<'a> {
    Surface(AiSurfaceStreamRewriter<'a>),
    WorkbuddyDsml(crate::ai_serving::transport::workbuddy_dsml::WorkbuddyDsmlStreamRepair),
}

pub(crate) fn maybe_build_local_stream_rewriter<'a>(
    report_context: Option<&'a Value>,
) -> Option<LocalStreamRewriter<'a>> {
    if let Some(inner) = maybe_build_ai_surface_stream_rewriter(report_context) {
        return Some(LocalStreamRewriter::Surface(inner));
    }
    // 同格式 WorkBuddy 流：改写矩阵与状态机都在格式 crate 的 provider_compat 里，
    // 这里只做委派（gateway 不拥有 provider 私有的流式细节）。
    crate::ai_serving::transport::workbuddy_dsml::maybe_build_workbuddy_dsml_stream_repair(
        report_context,
    )
    .map(LocalStreamRewriter::WorkbuddyDsml)
}

impl LocalStreamRewriter<'_> {
    pub(crate) fn into_owned(self) -> LocalStreamRewriter<'static> {
        match self {
            LocalStreamRewriter::Surface(inner) => LocalStreamRewriter::Surface(inner.into_owned()),
            // DSML 还原器自带全部状态（不借用 report_context），本身就是 'static。
            LocalStreamRewriter::WorkbuddyDsml(repair) => {
                LocalStreamRewriter::WorkbuddyDsml(repair)
            }
        }
    }

    pub(crate) fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, GatewayError> {
        match self {
            LocalStreamRewriter::Surface(inner) => {
                inner.push_chunk(chunk).map_err(map_surface_error)
            }
            LocalStreamRewriter::WorkbuddyDsml(repair) => Ok(repair.push_bytes(chunk)),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<u8>, GatewayError> {
        match self {
            LocalStreamRewriter::Surface(inner) => inner.finish().map_err(map_surface_error),
            LocalStreamRewriter::WorkbuddyDsml(repair) => Ok(repair.finish()),
        }
    }

    pub(crate) fn take_response_history_record(&mut self) -> Option<ResponseHistoryRecord> {
        match self {
            LocalStreamRewriter::Surface(inner) => inner.take_response_history_record(),
            // 直通流本来就不生成响应历史记录。
            LocalStreamRewriter::WorkbuddyDsml(_) => None,
        }
    }
}

fn map_surface_error(error: AiSurfaceFinalizeError) -> GatewayError {
    error.into()
}

#[cfg(test)]
#[path = "../tests_stream.rs"]
mod tests;
