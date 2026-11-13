from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from database.db import AssessmentDatabase


def test_assessment_database_supports_streamlit_worker_threads(tmp_path) -> None:
    database = AssessmentDatabase(str(tmp_path / 'assessments.sqlite3'))

    def save_and_list(index: int) -> list[dict]:
        database.save_assessment({
            'assessment_id': f'assessment-{index}',
            'category': 'wifi',
            'target': f'wlan{index}',
            'status': 'completed',
            'findings': [{
                'title': 'Configuration review',
                'severity': 'Informational',
                'status': 'Observed',
            }],
        })
        return database.list_assessments()

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(save_and_list, range(12)))

    assert all(result for result in results)
    history = database.list_assessments()
    assert len(history) == 12
    assert {item['id'] for item in history} == {
        f'assessment-{index}' for index in range(12)
    }
