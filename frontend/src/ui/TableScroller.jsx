import React, { useCallback, useEffect, useRef, useState } from "react";

/**
 * 가로 스크롤 표를 감싸고, **화면 아래에 붙는** 가로 스크롤바를 함께 그린다.
 *
 * 브라우저의 기본 가로 스크롤바는 스크롤 영역의 맨 아래에 있다. 행이 200개면 그 바는
 * 200행 아래에 있어서, 오른쪽 컬럼을 보려면 먼저 페이지 끝까지 내려가 바를 잡고 다시
 * 올라와야 한다. 실제로는 그냥 포기하고 컬럼을 지우게 된다.
 *
 * 그래서 같은 영역을 조종하는 프록시 바를 sticky 로 아래에 붙여 둔다. 표가 넘칠 때만
 * 나타나고(넘치지 않으면 화면에 군더더기를 더하지 않는다), 그때만 원래 스크롤바를 숨겨
 * 두 개가 겹쳐 보이지 않게 한다.
 */
export default function TableScroller({ children, label = "표 가로 스크롤" }) {
  const bodyRef = useRef(null);
  const barRef = useRef(null);
  // 한쪽을 움직이면 다른 쪽의 scroll 이벤트가 되돌아온다. 그 되울림으로 서로 밀어내면
  // 스크롤이 튀므로, 동기화 중에는 반대쪽 처리를 건너뛴다.
  const syncing = useRef(false);
  const [metrics, setMetrics] = useState({ scrollWidth: 0, clientWidth: 0 });

  const measure = useCallback(() => {
    const body = bodyRef.current;
    if (!body) return;
    setMetrics((prev) => (
      prev.scrollWidth === body.scrollWidth && prev.clientWidth === body.clientWidth
        ? prev
        : { scrollWidth: body.scrollWidth, clientWidth: body.clientWidth }
    ));
  }, []);

  useEffect(() => {
    const body = bodyRef.current;
    if (!body) return undefined;
    measure();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }
    // 컬럼을 켜고 끄면 표 자체의 폭이 바뀐다 — 컨테이너만 보면 그 변화를 놓친다.
    const observer = new ResizeObserver(measure);
    observer.observe(body);
    if (body.firstElementChild) observer.observe(body.firstElementChild);
    return () => observer.disconnect();
  }, [measure, children]);

  const overflowing = metrics.scrollWidth > metrics.clientWidth + 1;

  function sync(from, to) {
    if (syncing.current || !from || !to) return;
    syncing.current = true;
    to.scrollLeft = from.scrollLeft;
    // 이벤트 루프가 아니라 같은 프레임에서 풀어야, 사용자가 계속 드래그하는 동안
    // 중간 프레임이 통째로 버려지지 않는다.
    requestAnimationFrame(() => { syncing.current = false; });
  }

  return (
    <div className="table-scroller">
      <div
        className={"table-scroll" + (overflowing ? " has-proxy" : "")}
        ref={bodyRef}
        onScroll={() => sync(bodyRef.current, barRef.current)}
      >
        {children}
      </div>
      {overflowing && (
        <div
          className="table-scrollbar"
          ref={barRef}
          role="scrollbar"
          aria-label={label}
          aria-orientation="horizontal"
          onScroll={() => sync(barRef.current, bodyRef.current)}
        >
          <div className="table-scrollbar-span" style={{ width: metrics.scrollWidth }} />
        </div>
      )}
    </div>
  );
}
