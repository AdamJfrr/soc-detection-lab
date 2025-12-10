import { useState } from 'react';
import Modal from '../Modal';
import classes from './ScenarioBox.module.css';

const ScenarioBox = (props) => {
  const [open, setOpen] = useState(false);
  const [queryText, setQueryText] = useState('');
  const [queryTitle, setQueryTitle] = useState('');

  const openBasic = () => {
    setQueryTitle("Basic Query");
    setQueryText(props.basicQuery || "No basic query available.");
    setOpen(true);
  };

  const openAlert = () => {
    setQueryTitle("Alert Detection Query");
    setQueryText(props.alertQuery || "No alert query available.");
    setOpen(true);
  };

  return (
    <div className={classes.scenariobox}>
      <div className={classes.top}>
        <div className={classes.header}>
          {props.name} / Technique: {props.technique}
        </div>

        <div className={classes.description}>{props.scenario}</div>

        <div className={classes.requirements}>
          {props.requirements.map((req, idx) => (
            <div key={idx} className={classes.requirement}>- {req}</div>
          ))}
        </div>
      </div>

      <div className={classes.bottom}>
        <button className={classes.button1} onClick={openBasic}>Basic Query</button>
        <button className={classes.button2} onClick={openAlert}>Alert Detection Query</button>
      </div>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={queryTitle}
        query={queryText}
      />
    </div>
  );
};

export default ScenarioBox;
