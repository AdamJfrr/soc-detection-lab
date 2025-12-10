import LeftDiv from './components/left-container/LeftDiv';
import RightDiv from './components/right-container/RightDiv';
import  './App.css';
import {useState} from 'react';
import img_1 from './images/1.png';
import img_2 from './images/2.png';
import img_3 from './images/3.png';
import img_4 from './images/4.png';
import img_5 from './images/5.png';
import img_6 from './images/6.png';

function App() {
  const [id,setId] = useState(1)
  const [label,setLabel]=useState('Credential Access')
  const images = [img_1,img_2,img_3,img_4,img_5,img_6]
  const title_color = ['#C0A4FF','#A4FFB2','#DEFFA4','#FFEEA4','#A4E1FF','#FFA4A4']
  const assignPropsHandler = (id,label) => {
    setId(id)
    setLabel(label)
  }
  return (
    <div className="App">
      <LeftDiv forwardHandler={assignPropsHandler}/>
      <RightDiv title={label} img_source={images[id-1]} color={title_color[id-1]}/>
    </div>
  );
}

export default App;
