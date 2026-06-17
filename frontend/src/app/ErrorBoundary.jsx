import React from "react";

// 뷰별 크래시 격리 — App 에서 <ErrorBoundary key={view}> 로 감싸 한 탭의 예외가
// 앱 전체를 빈 화면으로 만들지 않게 한다(HANDOFF 함정 대응).
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // 콘솔에 남겨 CDP E2E 가 잡을 수 있게 한다.
    console.error("[ErrorBoundary]", error, info?.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel" style={{ margin: 24 }}>
          <h3 className="err">이 화면을 표시하는 중 오류가 발생했습니다</h3>
          <div className="pre">{String(this.state.error?.stack || this.state.error)}</div>
          <button className="sm" style={{ marginTop: 12 }} onClick={() => this.setState({ error: null })}>
            다시 시도
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
